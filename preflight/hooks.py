import sys
import json
import subprocess
from preflight.engine import evaluate_action
from preflight.audit import write_audit_log

def tool_to_action(tool_name, tool_input):
    if tool_name == "Bash":
        return {"type": "shell", "command": tool_input.get("command", "")}
    path = tool_input.get("file_path", "")
    if tool_name == "Write":
        return {"type": "write", "path": path, "content": tool_input.get("content", "")}
    if tool_name == "Edit":
        return {"type": "write", "path": path, "content": tool_input.get("new_string", "")}
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits", [])
        return {"type": "write", "path": path, "content": "\n".join(e.get("new_string", "") for e in edits)}
    return None

def handle_claude_code(policy_path: str):
    from preflight.cli import load_policy 
    
    policy = load_policy(policy_path, exit_code=2)
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    action = tool_to_action(tool_name, tool_input)

    if not action:
        sys.exit(0)

    result = evaluate_action(action, policy)
    write_audit_log(action, result)

    if result["decision"] == "deny":
        messages = " | ".join([r["message"] for r in result.get("matched_rules", [])])
        print(f"Preflight Blocked: {messages}", file=sys.stderr)
        sys.exit(2)
    elif result["decision"] == "warn":
        messages = " | ".join([r["message"] for r in result.get("matched_rules", [])])
        print(f"Preflight Warning: {messages}", file=sys.stderr)
        
    sys.exit(0)

def handle_git_pre_commit(policy_path: str):
    from preflight.cli import load_policy
    
    policy = load_policy(policy_path, exit_code=1)
    
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], 
        capture_output=True, text=True
    ).stdout.strip('\0').split('\0')
    
    staged_files = [f for f in staged if f]
    
    if not staged_files:
        sys.exit(0)
        
    diff_out = subprocess.run(
        ["git", "diff", "--cached", "-U0"], 
        capture_output=True, text=True
    ).stdout

    files_content = {}
    current_file = None
    in_hunk = False

    for line in diff_out.splitlines():
        if line.startswith("diff --git"):
            in_hunk = False
            current_file = None
        elif line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in files_content:
                files_content[current_file] = []
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith("+"):
            if current_file is not None:
                files_content[current_file].append(line[1:])

    blocked = False
    for filepath, lines in files_content.items():
        if not lines: 
            continue
            
        added_lines = "\n".join(lines)
        action = {"type": "write", "path": filepath, "content": added_lines}
        result = evaluate_action(action, policy)
        write_audit_log(action, result)

        if result["decision"] == "deny":
            messages = " | ".join([r["message"] for r in result.get("matched_rules", [])])
            print(f"❌ Blocked commit for {filepath}: {messages}", file=sys.stderr)
            blocked = True
        elif result["decision"] == "warn":
            messages = " | ".join([r["message"] for r in result.get("matched_rules", [])])
            print(f"⚠️ Warning for {filepath}: {messages}", file=sys.stderr)

    if blocked:
        print("\nCommit rejected by AI Policy Preflight.", file=sys.stderr)
        sys.exit(1)
    
    sys.exit(0)