PrivEsc-Detector
Privilege Escalation Detector — real-time, eBPF-based detection of Linux privilege-escalation attempts.
[!Python](detector/main.py)
[!eBPF / BCC](detector/ebpf/syscall_monitor.c)
[!Platform](detector/setup.sh)
[!Database](detector/database/schema.sql)
[!Service](detector/systemd/privilege-esc-detector.service)
PrivEsc-Detector watches privilege-related syscalls in real time with eBPF, matches them against a set of strict, true-positive-oriented rules, and stores every alert in a local SQLite database. A separate forwarder service can push new alerts to a cloud dashboard.
For authorised defensive use only. Run this only on systems you own or are explicitly authorised to monitor. It is a detection tool, not an exploitation tool.

How it works
Syscalls (kernel) ──eBPF tracepoints──▶ Ring buffer ──▶ Detection Engine
                                                              │
                                        ┌─────────────────────┼─────────────────────┐
                                        ▼                     ▼                     ▼
                                  Rules (RULE-01…10)   Anomaly detector   Baseline manager
                                        │              (disabled by default)
                                        ▼
                                  Alert Manager
                                  (dedup + rate-limit)
                                        │
                                        ▼
                              SQLite — data/database/detector.db
                                        │
                                        ▼
                              Forwarder ──▶ Cloud dashboard (Vercel, /api/alerts/ingest)
Collect — detector/ebpf/syscall_monitor.c attaches eBPF tracepoints to privilege-related syscalls and streams events through a ring buffer. detector/ebpf/loader.py (BCC) compiles and loads it.
Detect — detector/detection/engine.py runs a multi-threaded worker pool (4 workers by default) that feeds each event to detector/detection/rules.py. If BCC/eBPF is unavailable, the engine logs a warning and continues in limited mode.
Alert — detector/detection/alert.py deduplicates alerts (10-minute window), rate-limits them (20/minute by default), assigns a deterministic alert ID, and persists them to SQLite.
Forward (optional) — detector/forwarder/forwarder.py polls the database every 30 seconds and POSTs new alerts in batches of up to 50 to a Vercel dashboard.

Features
Real-time eBPF monitoring of setuid, setreuid, setresuid, setgid, execve, openat, chmod, and capset (plus seteuid in config.yaml)
10 strict detection rules (RULE-01 – RULE-10), all CRITICAL, designed for zero false positives — with safe-process allowlists (e.g. sudo, su, sshd, visudo, dpkg/apt) built into the rules
Correlation (RULE-10) — 2+ different escalation signals from the same PID within 15 seconds raises a Confirmed Privilege Escalation alert
Alert deduplication and rate limiting so one attack does not flood the database
Per-UID syscall baselines (detector/detection/baseline.py, stored as data/baselines/baseline_<uid>.json) and a statistical anomaly detector (detector/detection/anomaly.py) — anomaly detection is disabled by default in config.yaml
SQLite storage — alerts, events, and statistics tables, 30-day retention by default
Cloud forwarder — optional background service that syncs alerts to a Vercel dashboard, with retries and a local forwarder.config.json (mode 0600)
systemd services for both the detector and the forwarder, with automatic restart
One-command install / uninstall via setup.sh / uninstall.sh
Reports — full project and VAPT reports in Reports/

Detection rules
All rules are enabled by default in detector/config.yaml and can be toggled individually by rule_id.
Rule
Name
What it catches
RULE-01
Direct UID to Root
Non-root process (UID ≥ 1000) calling setuid / setreuid / setresuid to UID 0, excluding sudo, su, pkexec, passwd, etc.
RULE-02
Credential File Tampering
Unexpected process writing to /etc/shadow or /etc/gshadow
RULE-03
Root SSH Key Injection
Unexpected process accessing anything under /root/.ssh/
RULE-04
Process Memory Injection
Write access to /proc/<pid>/mem
RULE-05
Kernel Module Abuse
Non-root user running insmod, modprobe, or rmmod
RULE-06
Docker Socket Abuse
Unexpected process accessing /var/run/docker.sock or /run/docker.sock
RULE-07
SUID Binary from Writable Path
Root (euid == 0) execve from /tmp/, /dev/shm/, or /var/tmp/ by a non-root user
RULE-08
Capability Abuse
capset followed by a root execve from the same PID within 5 seconds
RULE-09
Sudoers Tampering
Unexpected process modifying /etc/sudoers
RULE-10
Confirmed Privilege Escalation
2+ different signals from the same PID within 15 seconds
Sensitive paths watched: /etc/shadow, /etc/gshadow, /etc/passwd, /etc/sudoers, /root/.ssh/.
Suspicious (writable) paths: /tmp/, /dev/shm/, /var/tmp/.
Whitelisted processes (skipped by the engine): systemd, systemd-journald, systemd-logind, systemd-udevd, sshd, cron, dpkg, apt, apt-get — see whitelist in detector/config.yaml.

Project structure
PrivEsc-Detector/
├── README.md
├── Reports/
│   ├── PrivEsc Project Report.pdf   # 61-page project report
│   └── PrivEsc VAPT Report.pdf      # 22-page VAPT report
└── detector/
    ├── main.py                      # Entry point: --config, --debug, --test
    ├── config.yaml                  # All configuration (rules, eBPF, DB, alerts, forwarder)
    ├── requirements.txt             # Python deps (see note below)
    ├── setup.sh                     # Install to /opt/privilege-escalation-detector
    ├── uninstall.sh                 # Remove services, install dir, and DB files
    ├── database/
    │   ├── schema.sql               # alerts / events / statistics tables
    │   ├── connection.py
    │   └── operations.py
    ├── detection/
    │   ├── engine.py                # Worker pool, whitelist, rule + anomaly dispatch
    │   ├── rules.py                 # RULE-01 … RULE-10
    │   ├── alert.py                 # Dedup (10 min), rate limit, persistence
    │   ├── anomaly.py               # Statistical deviation from baseline
    │   └── baseline.py              # Per-UID syscall baselines (JSON)
    ├── ebpf/
    │   ├── syscall_monitor.c        # eBPF tracepoint program
    │   ├── loader.py                # BCC loader + ring-buffer reader
    │   └── hooks.h
    ├── forwarder/
    │   ├── forwarder.py             # SQLite → Vercel /api/alerts/ingest
    │   └── privesc-forwarder.service
    ├── systemd/
    │   └── privilege-esc-detector.service
    └── utils/
        ├── config.py                # YAML config loader (dot-notation)
        ├── logger.py                # Colour console + rotating file logging
        └── helpers.py

Requirements
Linux (eBPF tracepoints + systemd) — not Windows/macOS
Root — setup and the detector itself must run as root
Python 3
bpfcc-tools, python3-bpfcc, and matching linux-headers-$(uname -r) — installed by setup.sh via apt
sqlite3
Note on requirements.txt: every line in detector/requirements.txt is currently commented out (bcc, pyyaml, requests, python-dotenv). pip install -r requirements.txt therefore installs nothing — BCC is provided by the apt packages above. If you uncomment those lines, make sure pyyaml is installed, as utils/config.py imports yaml.

Quick start
git clone https://github.com/fuzzzer77/PrivEsc-Detector.git
cd PrivEsc-Detector/detector

# Installs to /opt/privilege-escalation-detector,
# initialises the SQLite DB, installs + enables the systemd services
sudo bash setup.sh

# Start / check it
sudo systemctl start privilege-esc-detector
sudo systemctl status privilege-esc-detector
sudo journalctl -u privilege-esc-detector -f

# Logs are also at /opt/privilege-escalation-detector/logs/detector.log
Run without installing (foreground)
cd detector
sudo python3 main.py
sudo python3 main.py --config config.yaml --debug
CLI flags: --config <path> (default config.yaml), --debug, --test.
Stop / uninstall
sudo systemctl stop privilege-esc-detector
sudo bash uninstall.sh   # stops + disables services, removes /opt/privilege-escalation-detector and detector.db files

Configuration
All settings live in detector/config.yaml. Key sections:
Section
What it controls
Defaults
app
Name, version (1.0.0), environment, debug
production, debug off
ebpf
Enable, buffer size, sample rate, monitored syscalls
enabled, buffer 256
detection
Rules on/off, per-rule toggles, anomaly detection
rules on, anomaly off
database
SQLite path, retention, cleanup interval
data/database/detector.db, 30 days
dashboard
Dashboard integration
disabled
forwarder
Poll interval, batch size, retries
30 s, 50, 3 attempts
logging
Level, file + console, rotation
INFO, 10 MB × 5 files
alerts
Aggregation (60 s), rate limit, auto-response, notifications
20/min, auto-response + email/SMS/Slack/syslog off
performance
Throughput and resource caps
10,000 events/s, queue 1000, 4 workers, 512 MB, 10% CPU
whitelist
Processes/users skipped by the engine
see Rules section
sensitive_paths / suspicious_paths
Paths the rules watch
/etc/shadow, /etc/sudoers, /root/.ssh/, /tmp/, …
Edit config.yaml and restart the service to apply changes:
sudo systemctl restart privilege-esc-detector

Cloud forwarder (optional)
The forwarder reads new (unforwarded) alerts from SQLite and POSTs them to a Vercel dashboard at <vercel_url>/api/alerts/ingest with an X-API-Key header.
# First-time interactive setup — asks for Vercel URL, API key, machine name
# and saves them to forwarder/forwarder.config.json (0600)
sudo python3 /opt/privilege-escalation-detector/forwarder/forwarder.py --setup

# Check config / sync state
sudo python3 /opt/privilege-escalation-detector/forwarder/forwarder.py --status

# Run as a service (installed by setup.sh)
sudo systemctl enable privesc-forwarder
sudo systemctl start privesc-forwarder
sudo journalctl -u privesc-forwarder -f
If the forwarder is not configured, the detector still works fully locally — forwarding is optional.

Database
SQLite database at data/database/detector.db (default), created from detector/database/schema.sql during setup.
alerts — one row per alert: alert_id, rule_id, rule_name, severity, confidence, description, pid/ppid, uid/new_uid, comm/parent_comm, syscall, filename, timestamp, acknowledged, forwarded, created_at
events — raw syscall events
statistics — events_processed, alerts_generated, rules_triggered, anomalies_detected
Quick check:
sqlite3 /opt/privilege-escalation-detector/data/database/detector.db \
  "SELECT rule_id, rule_name, severity, comm, created_at FROM alerts ORDER BY created_at DESC LIMIT 20;"

Reports
Reports/PrivEsc Project Report.pdf — full project report (61 pages)
Reports/PrivEsc VAPT Report.pdf — VAPT report (22 pages)

Limitations & notes
Linux + root + BCC only. Without BCC the detector logs a warning and runs in limited mode — no syscall events are collected.
Anomaly detection and the dashboard are disabled by default (detection.anomaly_enabled: false, dashboard.enabled: false). The baseline/anomaly code exists, but it only runs when you enable it in config.yaml.
Auto-response and all notifications are off by default (alerts.auto_response.enabled: false, email/SMS/Slack/syslog off). The detector alerts and records; it does not block or kill processes on its own.
No test suite or license file is included in the repo at present.
The forwarder.config.json referenced in config.yaml is created by forwarder.py --setup; it does not ship in the repo.

Contributing
Issues and pull requests are welcome. If you add a rule, follow the existing pattern in detector/detection/rules.py — one RULE-XX block, a safe-process allowlist where a legitimate tool can trigger it, and a register(pid, …) call so RULE-10 correlation still works — and add the rule to rules_config in detector/config.yaml.

Disclaimer
This project is for defensive security research and authorised monitoring only. Do not deploy it on systems you do not own or do not have explicit permission to monitor, and do not use it to facilitate unauthorised access.
