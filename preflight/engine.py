from typing import Dict, Any, List
from preflight.models import Policy
from preflight.normalizers import apply_normalizers
from preflight.matchers import evaluate_match

def evaluate_action(action: Dict[str, Any], policy: Policy) -> Dict[str, Any]:
    action_type = action.get("type")
    matched_rules: List[Dict[str, Any]] = []
    normalized_used = False

    for rule in policy.rules:
        if action_type not in rule.applies_to:
            continue

        field_name = rule.match.field
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