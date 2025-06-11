import json
import os
import re
from time import sleep
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

# --- Configuration ---
MODEL_NAME = "google/flan-t5-small"
INPUT_FILE = "./data/cve_2023_preprocessed.json"
OUTPUT_FILE = "./data/cve_2023_llm_enriched.json"
DEBUG_FILE = "./data/sample_debug_output.txt"
MAX_CVES = 10

# --- Prompt Template ---
PROMPT_TEMPLATE = """Extract cybersecurity ontology elements from the following vulnerability description as JSON:
{{
  "classes": ["..."],
  "relations": [{{"subject": "", "predicate": "", "object": ""}}],
  "axioms": ["..."]
}}

Input: {input}
Answer:"""

# --- Model Loader ---
def load_model():
    print("⏳ Loading Flan-T5 small model (CPU)...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME)
    print("✅ Model loaded.")
    return tokenizer, model

# --- JSON Extractor ---
def extract_json(text):
    match = re.search(r'{.*}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            print("⚠️ Could not parse JSON.")
    return {"classes": [], "relations": [], "axioms": []}

# --- LLM Inference ---
def call_llm(prompt, cve_id, tokenizer, model):
    try:
        input_text = PROMPT_TEMPLATE.format(input=prompt)
        inputs = tokenizer(input_text, return_tensors="pt", truncation=True)
        outputs = model.generate(
            **inputs,
            max_new_tokens=120,
            do_sample=False
        )
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Truncate safely
        truncated = response.split("}", 1)[0] + "}"

        # Save debug
        with open(DEBUG_FILE, "a", encoding="utf-8") as dbg:
            dbg.write(f"\n\n--- {cve_id} ---\n{truncated}\n")

        return extract_json(truncated)

    except Exception as e:
        print(f"⚠️ Error for {cve_id}: {str(e)[:100]}...")
        return {"classes": [], "relations": [], "axioms": []}

# --- Batch Execution ---
def run_batch():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)[:MAX_CVES]

    tokenizer, model = load_model()
    output = []

    print(f"🔍 Processing {len(records)} CVEs...")
    for i, item in enumerate(records, 1):
        print(f"[{i}/{len(records)}] CVE: {item['id']}")
        enriched = call_llm(item["prompt_input"], item["id"], tokenizer, model)
        output.append({
            "id": item["id"],
            "prompt_input": item["prompt_input"],
            "llm_output": enriched
        })

        if i % 5 == 0:
            with open("data/tmp_autosave.json", "w", encoding="utf-8") as tmpf:
                json.dump(output, tmpf, indent=2)

        sleep(1)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"💾 Saved enriched CVEs to {OUTPUT_FILE}")

if __name__ == "__main__":
    run_batch()
