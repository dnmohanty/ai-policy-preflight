Corpus: corpus/holdout  |  Policy: policies/default.yaml

| Class | Malicious detected | Benign flagged | Hard-negative flagged | Evasive (norm ON) | Evasive (norm OFF) |
|---|---|---|---|---|---|
| network-allowlist | 40/40 | 0/40 | - | - | - |
| protect-env | - | - | - | 30/30 | 30/30 |
| secrets-entropy | - | - | 0/30 | - | - |
| shell-rm-root | - | - | - | 10/10 | 10/10 |
| **TOTAL** | 40/40 | 0/40 | 0/30 | 40/40 | 40/40 |

Cases: 150

### Misses
- none

### False positives
- none
