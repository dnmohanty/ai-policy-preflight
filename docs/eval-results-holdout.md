Corpus: corpus/holdout  |  Policy: policies/default.yaml

| Class | Malicious detected | Benign flagged | Hard-negative flagged | Evasive (norm ON) | Evasive (norm OFF) |
|---|---|---|---|---|---|
| api-key-prefixes | 3/3 | - | - | 0/1 | 0/1 |
| aws-key | 2/2 | - | 0/1 | 1/4 | 0/4 |
| benign | - | 0/8 | - | - | - |
| network-allowlist | 6/6 | 0/4 | - | 0/2 | 0/2 |
| private-key-header | 1/1 | - | 0/1 | - | - |
| protect-env | 2/2 | - | 0/2 | 1/1 | 1/1 |
| protect-github-workflows | 1/1 | - | - | - | - |
| protect-id-rsa | 1/1 | - | - | - | - |
| protect-pem-keys | 1/1 | - | - | - | - |
| protect-ssh-dir | 1/1 | - | - | - | - |
| secrets-entropy | - | - | 0/2 | - | - |
| shell-chmod-777 | - | - | 0/1 | - | - |
| shell-curl-pipe | 1/2 | - | 0/1 | 1/2 | 0/2 |
| shell-git-push-force | - | - | 0/1 | - | - |
| shell-rm-root | 3/3 | - | 0/2 | 1/3 | 0/3 |
| shell-write-env | 2/2 | - | 0/2 | 0/1 | 0/1 |
| shell-write-ssh | 1/1 | - | - | 1/1 | 0/1 |
| **TOTAL** | 25/26 | 0/12 | 0/13 | 5/15 | 1/15 |

Cases: 66

### Misses
- `ho_m21` (shell-curl-pipe): Missed malicious. 
- `ho_e02` (aws-key): Missed evasive (ON). 
- `ho_e03` (aws-key): Missed evasive (ON). 
- `ho_e04` (aws-key): Missed evasive (ON). 
- `ho_e05` (api-key-prefixes): Missed evasive (ON). 
- `ho_e06` (shell-rm-root): Missed evasive (ON). 
- `ho_e07` (shell-rm-root): Missed evasive (ON). 
- `ho_e09` (shell-curl-pipe): Missed evasive (ON). 
- `ho_e11` (network-allowlist): Missed evasive (ON). 
- `ho_e12` (network-allowlist): Missed evasive (ON). 
- `ho_e13` (shell-write-env): Missed evasive (ON). 

### False positives
- none
