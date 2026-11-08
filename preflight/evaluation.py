import json
import os
import glob
from collections import defaultdict
from preflight.engine import evaluate_action

def evaluate_corpus(corpus_dir: str, policy_path: str, output_json: str = None, output_md: str = None):
    from preflight.cli import load_policy 
    
    policy = load_policy(policy_path)
    policy_no_norms = load_policy(policy_path)
    policy_no_norms.normalizers = []

    stats = defaultdict(lambda: {
        "malicious": 0, "malicious_caught": 0, 
        "benign": 0, "benign_flagged": 0, 
        "hard_negative": 0, "hard_negative_flagged": 0,
        "evasive": 0, "evasive_caught_on": 0, "evasive_caught_off": 0
    })
    misses = []
    false_positives = []

    def check_caught(res, exp_dec, exp_rule):
        if res["decision"] not in ["deny", "warn"]:
            return False
        if exp_dec and res["decision"] != exp_dec:
            return False
        if exp_rule and exp_rule not in [r["id"] for r in res.get("matched_rules", [])]:
            return False
        return True

    for filepath in glob.glob(os.path.join(corpus_dir, "*.jsonl")):
        with open(filepath, 'r') as f:
            for line in f:
                if not line.strip(): 
                    continue
                case = json.loads(line)
                rule_class = case.get("class", "unknown")
                category = case.get("category", "unknown")
                expected_decision = case.get("expected")
                expected_rule = case.get("expected_rule")
                
                res_on = evaluate_action(case["action"], policy)
                res_off = evaluate_action(case["action"], policy_no_norms)
                
                is_flagged_on = res_on["decision"] in ["deny", "warn"]

                if category == "malicious":
                    stats[rule_class]["malicious"] += 1
                    if check_caught(res_on, expected_decision, expected_rule):
                        stats[rule_class]["malicious_caught"] += 1
                    else:
                        misses.append({"id": case.get("id"), "class": rule_class, "reason": "Missed malicious", "note": case.get("note", "")})
                
                elif category == "benign":
                    stats[rule_class]["benign"] += 1
                    if is_flagged_on:
                        stats[rule_class]["benign_flagged"] += 1
                        false_positives.append({"id": case.get("id"), "class": rule_class, "reason": "Flagged benign", "note": case.get("note", "")})
                
                elif category == "hard_negative":
                    stats[rule_class]["hard_negative"] += 1
                    if is_flagged_on:
                        stats[rule_class]["hard_negative_flagged"] += 1
                        false_positives.append({"id": case.get("id"), "class": rule_class, "reason": "Flagged hard negative", "note": case.get("note", "")})
                
                elif category == "evasive":
                    stats[rule_class]["evasive"] += 1
                    if check_caught(res_on, expected_decision, expected_rule):
                        stats[rule_class]["evasive_caught_on"] += 1
                    else:
                        misses.append({"id": case.get("id"), "class": rule_class, "reason": "Missed evasive (ON)", "note": case.get("note", "")})
                    
                    if check_caught(res_off, expected_decision, expected_rule):
                        stats[rule_class]["evasive_caught_off"] += 1

    lines = [f"Corpus: {corpus_dir}  |  Policy: {policy_path}", "",
             "| Class | Malicious detected | Benign flagged | Hard-negative flagged | Evasive (norm ON) | Evasive (norm OFF) |",
             "|---|---|---|---|---|---|"]
    tot = defaultdict(int)
    for c, s_ in sorted(stats.items()):
        for k, v in s_.items():
            tot[k] += v
        def frac(a, b):
            return f"{s_[a]}/{s_[b]}" if s_[b] else "-"
        lines.append(f"| {c} | {frac('malicious_caught','malicious')} | {frac('benign_flagged','benign')} | "
                     f"{frac('hard_negative_flagged','hard_negative')} | {frac('evasive_caught_on','evasive')} | {frac('evasive_caught_off','evasive')} |")
    def tfrac(a, b):
        return f"{tot[a]}/{tot[b]}" if tot[b] else "-"
    lines.append(f"| **TOTAL** | {tfrac('malicious_caught','malicious')} | {tfrac('benign_flagged','benign')} | "
                 f"{tfrac('hard_negative_flagged','hard_negative')} | {tfrac('evasive_caught_on','evasive')} | {tfrac('evasive_caught_off','evasive')} |")
    lines += ["", f"Cases: {sum(tot[k] for k in ('malicious','benign','hard_negative','evasive'))}", "", "### Misses"]
    lines += [f"- `{m['id']}` ({m['class']}): {m['reason']}. {m['note']}" for m in misses] or ["- none"]
    lines += ["", "### False positives"]
    lines += [f"- `{f['id']}` ({f['class']}): {f['reason']}. {f['note']}" for f in false_positives] or ["- none"]
    text = "\n".join(lines)
    print(text)
    if output_md:
        with open(output_md, "w") as f:
            f.write(text + "\n")

    if output_json:
        with open(output_json, "w") as f:
            json.dump({"stats": stats, "misses": misses, "false_positives": false_positives}, f, indent=2)