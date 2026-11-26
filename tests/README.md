# tests/

Unit tests for the Security Center back ends. They run on any Linux machine with Python 3, without building the ISO and without root.

| File | What it tests |
|---|---|
| `test_detection.py` | Detection engine: Sigma rules, suppressions, correlation, MITRE ATT&CK mapping, audit log hash chain |
| `test_dfir.py` | DFIR: chain of custody (signature, custody log) and timeline sources |
| `test_ir_state.py` | Incident Response state: Python parser (`ir_state.py`) and writer (`opt/nefi/ir/state.sh`) |
| `test_monitoring.py` | Network monitoring: Suricata event aggregation, capture filters, PCAP summary |
| `test_response.py` | Incident handling: cases, chained timeline, playbooks, quarantine, indicators, report |
| `test_system_prevention.py` | System and Prevention: points per check, score history, CVE priority, undo of fixes |

Run them from the repository root:

```bash
for t in tests/test_*.py; do python3 "$t" || break; done
```

Each file can also be run on its own, for example `python3 tests/test_detection.py`.

## Forensic permissions test

`test-forensics-perms.sh` checks that collected evidence cannot be read by other users. It runs a real evidence collection, so run it **as root, only in a NEFI OS test virtual machine**:

```bash
sudo bash tests/test-forensics-perms.sh
```

The comments inside the tests are in Italian, like the rest of the code for now.
