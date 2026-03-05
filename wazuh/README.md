# Scrutiny — Wazuh Integration

Wazuh decoder and rules for ingesting Scrutiny JSON Lines syscall telemetry.

## File Layout

```
wazuh/
├── decoders/
│   └── scrutiny_decoder.xml    # JSON field extraction
└── rules/
    └── scrutiny_rules.xml      # Alert rules with MITRE ATT&CK mappings
```

## Prerequisites

- Wazuh Manager 4.x or later
- Scrutiny baseliner compiled with Phase 3+ (JSON logging enabled)
- Log files being written to `logs/<proc>/json/<timestamp>.jsonl`

## Deployment

### 1. Copy files to Wazuh

```bash
sudo cp scrutiny_decoder.xml /var/ossec/etc/decoders/
sudo cp scrutiny_rules.xml   /var/ossec/etc/rules/
```

### 2. Configure log monitoring in `ossec.conf`

Add a `<localfile>` block pointing at the Scrutiny JSON log directory.
Adjust the path to match your Scrutiny working directory:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/Scrutiny/logs/*/json/*.jsonl</location>
</localfile>
```

### 3. Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

### 4. Verify decoder and rules load cleanly

```bash
sudo /var/ossec/bin/ossec-logtest
```

Paste a sample JSON line from a `.jsonl` log and confirm the decoder
fires and the correct rule ID triggers.

Sample test input:
```
{"timestamp":"2026-03-05T19:54:47Z","pid":1089,"process":"targetProc2","syscall_num":44,"syscall_name":"sendto","risk_tier":"CRITICAL","risk_score":10}
```

Expected output:
```
**Phase 1: Completed filtering (rules).
Rule id: '200113'
Level: '12'
Description: 'Scrutiny: Network data transmission - sendto by targetProc2 [PID 1089]'
```

---

## Rule ID Reference

| Rule ID | Level | Trigger                                      | MITRE         |
|---------|-------|----------------------------------------------|---------------|
| 200100  | 0     | Base: any Scrutiny event                     |               |
| 200101  | 3     | LOW tier syscall                             |               |
| 200102  | 6     | MEDIUM tier syscall                          |               |
| 200103  | 9     | HIGH tier syscall                            |               |
| 200110  | 12    | CRITICAL tier (generic)                      |               |
| 200111  | 12    | execve / execveat                            | T1059         |
| 200112  | 12    | connect()                                    | T1071, T1071.001 |
| 200113  | 12    | sendto / sendmsg / sendmmsg                  | T1041         |
| 200114  | 12    | ptrace                                       | T1055         |
| 200115  | 12    | init_module / finit_module / delete_module   | T1547.006     |
| 200116  | 12    | kexec_load / kexec_file_load                 | T1542.001     |
| 200117  | 12    | bpf                                          | T1014         |
| 200118  | 12    | process_vm_writev                            | T1055.001     |
| 200120  | 15    | 5+ CRITICAL syscalls in 60s (same process)   |               |
| 200121  | 15    | 3+ connect() in 30s — C2 beacon pattern      | T1071, T1132  |
| 200122  | 15    | 3+ sendto() in 30s — exfil stream            | T1041         |

---

## Alert Level Reference

| Wazuh Level | Meaning                                      |
|-------------|----------------------------------------------|
| 3           | Informational / audit trail                  |
| 6           | Low-priority deviation from baseline         |
| 9           | Suspicious activity, investigation warranted |
| 12          | High-priority alert, immediate review        |
| 15          | Critical: active threat pattern confirmed    |

---

## Frequency Rules

Two frequency-based rules escalate to level 15 for sustained patterns:

- **200120** — 5+ CRITICAL syscalls within 60s from the same process
- **200121** — 3+ `connect()` calls within 30s (C2 beacon signature)
- **200122** — 3+ `sendto()`/`sendmsg()` calls within 30s (exfil stream)

These are designed to catch targetProc2-style attack patterns where
individual syscalls appear sporadically but sustained activity reveals
intent.

---

## CyberShield 2026 Demo Notes

For the HBV2.0 demonstration, the expected alert flow against
`targetProc2` is:

1. ~iter 20: `connect()` fires rule **200112** (level 12, T1071)
2. ~iter 40: `sendto()` fires rule **200113** (level 12, T1041)
3. Sustained run: rules **200121** and **200122** escalate to level 15

This maps cleanly to the 3-stage C2 lifecycle:
**Recon → Channel Establishment → Active Exfiltration**
