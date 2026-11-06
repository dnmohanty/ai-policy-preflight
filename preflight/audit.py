import json
import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, Any

def _hash_action(action: Dict[str, Any]) -> str:
    action_str = json.dumps(action, sort_keys=True)
    return hashlib.sha256(action_str.encode('utf-8')).hexdigest()

def write_audit_log(action: Dict[str, Any], result: Dict[str, Any], log_path: str = "./.preflight/audit.jsonl") -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": action.get("type", "unknown"),
        "decision": result.get("decision", "error"),
        "matched_rule_ids": [r["id"] for r in result.get("matched_rules", [])],
        "action_hash": _hash_action(action)
    }
    
    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")