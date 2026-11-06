import json
import os
import glob
from collections import defaultdict
from preflight.engine import evaluate_action

def evaluate_corpus(corpus_dir: str, policy_path: str, output_json: str = None):
    # Import moved INSIDE the function to prevent circular import error
    from preflight.cli import load_policy 
    
    policy = load_policy(policy_path)
    policy_no_norms = load_policy(policy_path)
    policy_no_norms.normalizers = []

    stats = defaultdict(lambda: {"malicious": 0, "malicious_caught": 0, "benign": 0, "benign_flagged": 0, "evasive": 0, "evasive_caught_on": 0, "evasive_caught_off": 0})
    misses = []
    false_positives = []

    for filepath in glob.glob(os.path.join(corpus_dir, "*.jsonl")):
        with open(filepath, 'r') as f:
            for line in f:
                if not line.strip(): continue
                case = json.loads(line)
                rule_class = case.get("class", "unknown")
                category = case["category"]
                
                res_on = evaluate_action(case["action"], policy)
                res_off = evaluate_action(case["action"], policy_no_norms)
                
                is_flagged_on = res_on["decision"] in ["deny", "warn"]
                is_flagged_off = res_off["decision"] in ["deny", "warn"]

                if category == "malicious":
                    stats[rule_class]["malicious"] += 1
                    if is_flagged_on:
                        stats[rule_class]["malicious_caught"] += 1
                    else:
                        misses.append({"id": case["id"], "class": rule_class, "reason": "Missed malicious"})
                elif category == "benign":
                    stats[rule_class]["benign"] += 1
                    if is_flagged_on:
                        stats[rule_class]["benign_flagged"] += 1
                        false_positives.append({"id": case["id"], "class": rule_class, "reason": "Flagged benign"})
                elif category == "evasive":
                    stats[rule_class]["evasive"] += 1
                    if is_flagged_on: stats[rule_class]["evasive_caught_on"] += 1
                    else: misses.append({"id": case["id"], "class": rule_class, "reason": "Missed evasive (ON)"})
                    if is_flagged_off: stats[rule_class]["evasive_caught_off"] += 1

    print(f"{'Class':<20} | {'Malicious (TPR)':<17} | {'Benign (FPR)':<15} | {'Evasive (ON)':<15} | {'Evasive (OFF)'}")
    print("-" * 85)
    for c, s in stats.items():
        tpr = f"{s['malicious_caught']}/{s['malicious']}" if s['malicious'] else "N/A"
        fpr = f"{s['benign_flagged']}/{s['benign']}" if s['benign'] else "N/A"
        ev_on = f"{s['evasive_caught_on']}/{s['evasive']}" if s['evasive'] else "N/A"
        ev_off = f"{s['evasive_caught_off']}/{s['evasive']}" if s['evasive'] else "N/A"
        print(f"{c:<20} | {tpr:<17} | {fpr:<15} | {ev_on:<15} | {ev_off}")
    
    print("\nMisses:", [m["id"] for m in misses])
    print("False Positives:", [fp["id"] for fp in false_positives])
    
    if output_json:
        with open(output_json, "w") as f:
            json.dump({"stats": stats, "misses": misses, "false_positives": false_positives}, f, indent=2)