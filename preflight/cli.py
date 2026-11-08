import argparse
import sys
import json
import yaml
from pydantic import ValidationError
from preflight.models import Policy
from preflight.engine import evaluate_action
from preflight.audit import write_audit_log
from preflight.evaluation import evaluate_corpus
from preflight.hooks import handle_claude_code, handle_git_pre_commit

def load_policy(path: str, exit_code: int = 65) -> Policy:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return Policy(**data)
    except FileNotFoundError:
        print(f"Error: Policy file {path} not found.", file=sys.stderr)
        sys.exit(exit_code)
    except ValidationError as e:
        print(f"Policy validation error in {path}:", file=sys.stderr)
        for err in e.errors():
            loc = " -> ".join(map(str, err['loc']))
            print(f"  {loc}: {err['msg']}", file=sys.stderr)
        sys.exit(exit_code)
    except yaml.YAMLError as e:
        print(f"YAML parsing error in {path}: {e}", file=sys.stderr)
        sys.exit(exit_code)

def check_action(args):
    policy = load_policy(args.policy)
    
    if args.file:
        try:
            with open(args.file, "r") as f:
                action = json.load(f)
        except Exception as e:
            print(f"Error reading action file: {e}", file=sys.stderr)
            sys.exit(64)
    else:
        try:
            action = json.load(sys.stdin)
        except Exception as e:
            print(f"Error reading action from stdin: {e}", file=sys.stderr)
            sys.exit(64)

    if not isinstance(action, dict) or "type" not in action:
        print("Invalid action format. Must be a JSON object with a 'type' field.", file=sys.stderr)
        sys.exit(64)

    result = evaluate_action(action, policy)
    
    if not args.no_audit:
        write_audit_log(action, result)
        
    print(json.dumps(result))
    
    if result["decision"] == "allow":
        sys.exit(0)
    elif result["decision"] == "deny":
        sys.exit(1)
    elif result["decision"] == "warn":
        sys.exit(2)

def validate_policy_cmd(args):
    load_policy(args.policy)
    print(f"Policy {args.policy} is valid.")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="AI Policy Preflight")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--policy", required=True)
    check_parser.add_argument("--file")
    check_parser.add_argument("--no-audit", action="store_true")
    check_parser.set_defaults(func=check_action)

    validate_parser = subparsers.add_parser("validate-policy")
    validate_parser.add_argument("policy")
    validate_parser.set_defaults(func=validate_policy_cmd)

    eval_parser = subparsers.add_parser("eval")
    eval_parser.add_argument("--corpus", required=True)
    eval_parser.add_argument("--policy", required=True)
    eval_parser.add_argument("--json")
    eval_parser.add_argument("--md", help="write the results table to this markdown file")
    eval_parser.set_defaults(func=lambda a: evaluate_corpus(a.corpus, a.policy, a.json, a.md))

    hook_parser = subparsers.add_parser("hook")
    hook_parser.add_argument("agent", choices=["claude-code"])
    hook_parser.add_argument("--policy", default="policies/default.yaml")
    hook_parser.set_defaults(func=lambda a: handle_claude_code(a.policy))

    staged_parser = subparsers.add_parser("scan-staged")
    staged_parser.add_argument("--policy", default="policies/default.yaml")
    staged_parser.set_defaults(func=lambda a: handle_git_pre_commit(a.policy))

    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()