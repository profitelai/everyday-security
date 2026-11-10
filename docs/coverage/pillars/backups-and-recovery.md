# Backups and recovery

[← Coverage](../README.md)

3-2-1 copies, offsite and immutable copies, restore tests, retention, database dumps.

**9 checks** · 0 run automatically · 0 in the server audit · 9 guided checklists · for: Any business running systems

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [BAK-001](../../kb/backups-and-recovery/BAK-001.md) | Backups run on a schedule and a missed or failed run raises an alert | high | Guided checklist | NIST SP 800-53 CP-9 |
| [BAK-002](../../kb/backups-and-recovery/BAK-002.md) | Important data exists in at least three copies, on two kinds of storage, with one off-site | high | Guided checklist | - |
| [BAK-003](../../kb/backups-and-recovery/BAK-003.md) | Backups are encrypted and the key is stored apart from the backups | high | Guided checklist | - |
| [BAK-004](../../kb/backups-and-recovery/BAK-004.md) | An attacker who controls the server cannot delete or alter its backups | high | Guided checklist | - |
| [BAK-005](../../kb/backups-and-recovery/BAK-005.md) | Restores are tested regularly and the result is written down | high | Guided checklist | NIST SP 800-53 CP-4, NIST SP 800-53 CP-9 |
| [BAK-006](../../kb/backups-and-recovery/BAK-006.md) | Databases are backed up with a consistent method, not by copying live files | high | Guided checklist | - |
| [BAK-007](../../kb/backups-and-recovery/BAK-007.md) | Retention keeps old restore points, not only yesterday's | medium | Guided checklist | - |
| [BAK-008](../../kb/backups-and-recovery/BAK-008.md) | Recovery objectives (RPO and RTO) are documented, with a short recovery runbook | medium | Guided checklist | NIST SP 800-34 Rev. 1 |
| [BAK-009](../../kb/backups-and-recovery/BAK-009.md) | Mail, uploaded files and configuration are recoverable, not only the database | high | Guided checklist | - |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
