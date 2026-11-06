from preflight.models import Policy, Rule, RegexMatch
from preflight.engine import evaluate_action

def test_engine_precedence():
    policy = Policy(
        default_decision="allow",
        rules=[
            Rule(
                id="deny-rule",
                applies_to=["shell"],
                match=RegexMatch(kind="regex", field="command", pattern="rm -rf"),
                decision="deny",
                message="Block rm"
            ),
            Rule(
                id="warn-rule",
                applies_to=["shell"],
                match=RegexMatch(kind="regex", field="command", pattern="sudo"),
                decision="warn",
                message="Warn sudo"
            )
        ]
    )
    
    action_deny = {"type": "shell", "command": "sudo rm -rf /"}
    result_deny = evaluate_action(action_deny, policy)
    assert result_deny["decision"] == "deny"
    assert len(result_deny["matched_rules"]) == 2

    action_warn = {"type": "shell", "command": "sudo ls"}
    result_warn = evaluate_action(action_warn, policy)
    assert result_warn["decision"] == "warn"
    assert len(result_warn["matched_rules"]) == 1

    action_allow = {"type": "shell", "command": "ls -la"}
    result_allow = evaluate_action(action_allow, policy)
    assert result_allow["decision"] == "allow"
    assert len(result_allow["matched_rules"]) == 0