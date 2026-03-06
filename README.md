# Scrutiny — HoneyBadger Vanguard Fork

> *"A babysitter for programs that haven't earned your trust."*

A Linux process behavioral baselining and anomaly detection tool.  
Scrutiny uses `ptrace` to trace syscalls made by a target process, establishes a behavioral baseline, then compares subsequent runs to detect deviations — the foundation of host-based behavioral EDR.

---

## Attribution

This project is a fork of the original **Scrutiny** by [CommonTongue-InfoSec](https://github.com/CommonTongue-InfoSec/Scrutiny).  
The core baselining engine, syscall table, and detection concept are their work.  
This fork extends the project with additional threat simulation targets, structured logging, and SIEM integration — built on top of a solid foundation. Respect.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Scrutiny                           │
│                                                         │
│  baseliner.c   ← ptrace syscall tracer (runs as root)   │
│  syscalls.c    ← x86_64 syscall lookup table (0–425)    │
│  utils.c       ← /proc/<pid>/comm process name helper   │
│                                                         │
│  targetProc0   ← Clean baseline: file I/O, PID checks   │
│  targetProc1   ← Dirty: access("/etc/shadow") at t=30   │
│  targetProc2   ← Network threat sim (3-stage)           │
│    Stage 1 (t=20): DNS beacon / C2 hostname resolution  │
│    Stage 2 (t=40): TCP connect to external IP           │
│    Stage 3 (t=60): UDP exfil send                       │
│                                                         │
│  monitor.py    ← Frequency-diff anomaly analysis (GUI)  │
└─────────────────────────────────────────────────────────┘
```

---

## Requirements

- Linux (x86_64)
- GCC
- Python 3 with tkinter: `sudo apt install python3-tk`
- Root privileges for baseliner

---

## Usage

### Build

```bash
sudo apt update
sudo apt install python3-tk
cd Scrutiny
make clean   # if rebuilding
make
```

### Baseline + Monitor (two terminals)

**Terminal 1 (user-level) — start target process:**
```bash
make run targetProc0      # clean baseline
# note the PID printed to stdout
```

**Terminal 2 (root) — attach baseliner:**
```bash
sudo make run baseliner   # enter the PID from Terminal 1
```

Both processes exit together after ~2 minutes. Repeat with `targetProc1` or `targetProc2` to capture threat behavior.

### Analyze

```bash
cd src
python3 monitor.py
# GUI file picker: select targetProc0 log first, then targetProc1 or targetProc2 log
# Anomalies output to console
```

---

## Target Processes

| Binary | Behavior | Anomalous Syscalls |
|---|---|---|
| `targetProc0` | Clean — file I/O, PID checks, time queries | None (baseline) |
| `targetProc1` | Dirty — same as 0, plus `/etc/shadow` probe at iter 30 | `access` (syscall 21) |
| `targetProc2` | Network threat sim — DNS beacon, TCP connect, UDP exfil | `socket`, `connect`, `sendto` |

---

## Roadmap

- [x] Phase 1 — targetProc2 full network threat simulation
- [ ] Phase 2 — Syscall risk scoring (weighted severity in monitor.py)
- [ ] Phase 3 — Structured JSON logging (primary) + CSV export
- [ ] Phase 4 — Wazuh decoder + rules with MITRE ATT&CK mapping
- [ ] Phase 5 — PowerShell wrapper for WSL2 / Windows integration

---

## Project Context

This fork is part of **HoneyBadger Vanguard (HBV2.0)** — an AI-powered active defense research platform built for demonstration at [CyberShield 2026](https://cyberShield.us).  
*Understand offense. Build better defense.*

---

## License

See original repository: [CommonTongue-InfoSec/Scrutiny](https://github.com/CommonTongue-InfoSec/Scrutiny)
