import json
import os
from time import sleep

# Mock function to simulate OpenAI call
def call_llm(prompt, cve_id=None):
    print(f"Mocking response for {cve_id}")
    return {
        "classes": ["RaceCondition", "KernelModule"],
        "relations": [
            {"subject": "Exploit", "predicate": "targets", "object": "KernelModule"}
        ],
        "axioms": [
            "RaceCondition ⊑ SoftwareFlaw",
            "HighSeverity ⊑ requiresImmediateMitigation"
        ]
    }

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_batch(
    infile=os.path.join(SCRIPT_DIR, "data", "cve_2023_preprocessed.json"),
    outfile=os.path.join(SCRIPT_DIR, "data", "cve_2023_llm_output.json"),
   limit=None
):
    # ✅ Ensure output directory exists
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    if not os.path.exists(infile):
        raise FileNotFoundError(f"Input file {infile} not found.")

    with open(infile, "r", encoding="utf-8") as f:
        records = json.load(f)

    output = []
    for i, item in enumerate(records[:limit]):
        print(f"[{i+1}] CVE: {item['id']}")
        mock_output = call_llm(item["prompt_input"], cve_id=item["id"])
        output.append({
            "id": item["id"],
            "prompt_input": item["prompt_input"],
            "llm_output": mock_output
        })
        sleep(1)

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"✅ Mocked LLM output saved to {outfile}")

if __name__ == "__main__":
    run_batch()
