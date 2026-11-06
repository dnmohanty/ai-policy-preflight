import json
import os
import glob
from collections import defaultdict
from preflight.engine import evaluate_action

def evaluate_corpus(corpus_dir: str, policy_path: str, output_json: str = None):
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
                        misses.append({"id": case.get("id"), "class": rule_class, "reason": "Missed malicious"})
                
                elif category == "benign":
                    stats[rule_class]["benign"] += 1
                    if is_flagged_on:
                        stats[rule_class]["benign_flagged"] += 1
                        false_positives.append({"id": case.get("id"), "class": rule_class, "reason": "Flagged benign"})
                
                elif category == "hard_negative":
                    stats[rule_class]["hard_negative"] += 1
                    if is_flagged_on:
                        stats[rule_class]["hard_negative_flagged"] += 1
                        false_positives.append({"id": case.get("id"), "class": rule_class, "reason": "Flagged hard negative"})
                
                elif category == "evasive":
                    stats[rule_class]["evasive"] += 1
                    if check_caught(res_on, expected_decision, expected_rule):
                        stats[rule_class]["evasive_caught_on"] += 1
                    else:
                        misses.append({"id": case.get("id"), "class": rule_class, "reason": "Missed evasive (ON)"})
                    
                    if check_caught(res_off, expected_decision, expected_rule):
                        stats[rule_class]["evasive_caught_off"] += 1

    print(f"{'Class':<20} | {'Malicious (TPR)':<15} | {'Benign (FPR)':<14} | {'Hard Neg (FPR)':<14} | {'Evasive (ON)':<12} | {'Evasive (OFF)'}")
    print("-" * 100)
    for c, s in stats.items():
        tpr = f"{s['malicious_caught']}/{s['malicious']}" if s['malicious'] else "N/A"
        fpr = f"{s['benign_flagged']}/{s['benign']}" if s['benign'] else "N/A"
        hn_fpr = f"{s['hard_negative_flagged']}/{s['hard_negative']}" if s['hard_negative'] else "N/A"
        ev_on = f"{s['evasive_caught_on']}/{s['evasive']}" if s['evasive'] else "N/A"
        ev_off = f"{s['evasive_caught_off']}/{s['evasive']}" if s['evasive'] else "N/A"
        print(f"{c:<20} | {tpr:<15} | {fpr:<14} | {hn_fpr:<14} | {ev_on:<12} | {ev_off}")
    
    print("\nMisses:", [m.get("id") for m in misses])
    print("False Positives:", [fp.get("id") for fp in false_positives])
    
    if output_json:
        with open(output_json, "w") as f:
            json.dump({"stats": stats, "misses": misses, "false_positives": false_positives}, f, indent=2)