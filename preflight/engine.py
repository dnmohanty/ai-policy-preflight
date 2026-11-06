from typing import Dict, Any, List
from preflight.models import Policy
from preflight.normalizers import apply_normalizers
from preflight.matchers import evaluate_match

PRIMARY = {"shell": "command", "write": "content", "prompt": "text"}

def evaluate_action(action: Dict[str, Any], policy: Policy) -> Dict[str, Any]:
    action_type = action.get("type")
    
    command_val = action.get("command", "")
    content_val = action.get("content", "")
    text_val = action.get("text", "")
    
    if (isinstance(command_val, str) and len(command_val) > 20000) or \
       (isinstance(content_val, str) and len(content_val) > 1000000) or \
       (isinstance(text_val, str) and len(text_val) > 1000000):
        return {
            "decision": "warn",
            "matched_rules": [{
                "id": "preflight.input-too-large",
                "decision": "warn",
                "message": "Input exceeded size limits and was skipped."
            }],
            "normalized": False
        }

    matched_rules: List[Dict[str, Any]] = []
    normalized_used = False

    for rule in policy.rules:
        if action_type not in rule.applies_to:
            continue

        field_name = PRIMARY.get(action_type, "") if rule.match.field == "body" else rule.match.field
        raw_value = action.get(field_name, "")
        if not isinstance(raw_value, str):
            continue

        processed_value = raw_value
        if policy.normalizers:
            processed_value = apply_normalizers(raw_value, policy.normalizers)
            if processed_value != raw_value:
                normalized_used = True

        if evaluate_match(rule.match, processed_value):
            matched_rules.append({
                "id": rule.id,
                "decision": rule.decision,
                "message": rule.message
            })

    final_decision = policy.default_decision
    if any(r["decision"] == "deny" for r in matched_rules):
        final_decision = "deny"
    elif any(r["decision"] == "warn" for r in matched_rules):
        final_decision = "warn"

    return {
        "decision": final_decision,
        "matched_rules": matched_rules,
        "normalized": normalized_used
    }