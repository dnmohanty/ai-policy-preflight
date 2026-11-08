Corpus: corpus/dev  |  Policy: policies/default.yaml

| Class | Malicious detected | Benign flagged | Hard-negative flagged | Evasive (norm ON) | Evasive (norm OFF) |
|---|---|---|---|---|---|
| api-key-prefixes | 2/2 | - | - | - | - |
| aws-key | 3/3 | - | - | 2/5 | 1/5 |
| benign | - | 0/6 | - | - | - |
| hard-negative | - | - | 0/14 | - | - |
| network-allowlist | 4/4 | - | - | 0/1 | 0/1 |
| private-key-header | 1/1 | - | - | - | - |
| protect-env | 3/3 | - | - | - | - |
| protect-github-workflows | 1/1 | - | - | - | - |
| protect-id-rsa | 1/1 | - | - | - | - |
| protect-pem-keys | 1/1 | - | - | - | - |
| protect-ssh-dir | 1/1 | - | - | - | - |
| shell-chmod-777 | 1/1 | - | - | - | - |
| shell-curl-pipe | 3/3 | - | - | 1/2 | 0/2 |
| shell-git-push-force | 2/2 | - | - | - | - |
| shell-rm-root | 4/4 | - | - | 1/3 | 0/3 |
| shell-write-env | 2/2 | - | - | 0/1 | 0/1 |
| shell-write-ssh | 1/1 | - | - | - | - |
| warn-lockfiles-npm | 1/1 | - | - | - | - |
| **TOTAL** | 31/31 | 0/6 | 0/14 | 4/12 | 1/12 |

Cases: 63

### Misses
- `e05` (aws-key): Missed evasive (ON). 
- `e06` (aws-key): Missed evasive (ON). 
- `e07` (aws-key): Missed evasive (ON). 
- `e08` (shell-rm-root): Missed evasive (ON). 
- `e09` (shell-rm-root): Missed evasive (ON). 
- `e10` (network-allowlist): Missed evasive (ON). 
- `e11` (shell-write-env): Missed evasive (ON). 
- `e12` (shell-curl-pipe): Missed evasive (ON). 

### False positives
- none
