# Design & Architecture

AI Policy Preflight uses a deterministic, regex-based engine prioritizing zero false-positives over full theoretical coverage. 

### Match Order:
1. **Normalizers:** Input is processed (NFKC, whitespace collapse, quote stripping, base64 decoding) to strip basic evasions.
2. **Rules:** Configured YAML rules match sequentially against the normalized text.
3. **Decisions:** Rules resolve to `allow`, `warn`, or `deny`. A single `deny` overrides all others.
