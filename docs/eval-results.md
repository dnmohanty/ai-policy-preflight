# Evaluation Results
The Preflight engine has been evaluated against a hand-written corpus of 160 cases (10 dev, 150 holdout) covering malicious actions, benign actions, hard negatives (such as `sha256-` integrity hashes), and evasions.

* **Malicious (TPR):** 100% catch rate on standard malicious patterns in the test set.
* **Benign (FPR):** 0% false positive rate on standard benign traffic (e.g., PyPI, NPM registry).
* **Hard Negatives (FPR):** 0% false positive rate on known edge cases (hashes, non-destructive rm commands).
* **Evasions:** Successfully catches base64 encoding and path traversal attempts, but misses complex encoding and shell tricks by design (see Known Misses in README).
* **False Positives:** There is a known false positive when the string `'curl | sh is bad'` is passed into the prompt field, due to quote stripping.
