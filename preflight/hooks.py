import sys
import json
import subprocess
from preflight.engine import evaluate_action
from preflight.audit import write_audit_log

# Official Claude Code Hooks Documentation: 
# https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/hooks
# A PreToolUse hook receives a JSON object on stdin.
# It must print the block reason to stderr and exit with code 2 to block the action.
def handle_claude_code(policy_path: str):
    # Import moved INSIDE the function to prevent circular import
    from preflight.cli import load_policy 
    
    policy = load_policy(policy_path)
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0) # Not valid JSON, ignore

    # Map Claude Code's tool format to our ActionType format
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    action = None

    if tool_name == "Bash":
        action = {"type": "shell", "command": tool_input.get("command", "")}
    elif tool_name in ["Write", "Edit", "Replace"]:
        action = {"type": "write", "path": tool_input.get("file_path", ""), "content": tool_input.get("content", "")}
    
    if not action:
        sys.exit(0)

    result = evaluate_action(action, policy)
    write_audit_log(action, result)

    if result["decision"] == "deny":
        messages = " | ".join([r["message"] for r in result["matched_rules"]])
        print(f"Preflight Blocked: {messages}", file=sys.stderr)
        sys.exit(2) # Exit 2 is required by Claude Code to block

    sys.exit(0)

def handle_git_pre_commit(policy_path: str):
    # Import moved INSIDE the function to prevent circular import
    from preflight.cli import load_policy
    
    policy = load_policy(policy_path)
    
    # Get staged files
    staged_files = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True).stdout.splitlines()
    
    blocked = False
    for filepath in staged_files:
        if not filepath: continue
        
        # Get the added lines for the file
        diff = subprocess.run(["git", "diff", "--cached", filepath], capture_output=True, text=True).stdout
        added_lines = "\n".join([line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")])
        
        if not added_lines: continue

        action = {"type": "write", "path": filepath, "content": added_lines}
        result = evaluate_action(action, policy)
        write_audit_log(action, result)

        if result["decision"] == "deny":
            messages = " | ".join([r["message"] for r in result["matched_rules"]])
            print(f"❌ Blocked commit for {filepath}: {messages}", file=sys.stderr)
            blocked = True
        elif result["decision"] == "warn":
            messages = " | ".join([r["message"] for r in result["matched_rules"]])
            print(f"⚠️ Warning for {filepath}: {messages}", file=sys.stderr)

    if blocked:
        print("\nCommit rejected by AI Policy Preflight.", file=sys.stderr)
        sys.exit(1) # Git pre-commit uses exit code 1 to abort
    
    sys.exit(0)