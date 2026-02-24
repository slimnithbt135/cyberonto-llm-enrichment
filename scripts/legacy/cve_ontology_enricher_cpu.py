import json
import os
import torch
from time import sleep
from transformers import AutoModelForCausalLM, AutoTokenizer

# --- Configuration ---
MODEL_NAME = "openchat/openchat_3.5"  # Changed to open model
INPUT_FILE = "./data/cve_2023_preprocessed.json"
OUTPUT_FILE = "./data/cve_2023_llm_enriched.json"
MAX_CVES = 10  # Test with 10 CVEs first

# --- Model Loader ---
def load_model():
    print("⏳ Loading OpenChat 3.5 (CPU mode)...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        device_map="cpu",
        torch_dtype=torch.float32
    )
    print("✅ Model loaded")
    return tokenizer, model

# --- LLM Call ---
def call_llm(prompt, cve_id, tokenizer, model):
    try:
        text = f"""GPT4 Correct User: Extract cybersecurity ontology terms as JSON with:
{{
  "classes": ["list", "of", "concepts"],
  "relations": [{{"subject": "", "predicate": "", "object": ""}}],
  "axioms": ["list", "of", "rules"]
}}
Input: {prompt}<|end_of_turn|>GPT4 Correct Assistant:"""
        
        inputs = tokenizer(text, return_tensors="pt").to("cpu")
        outputs = model.generate(
            **inputs,
            max_new_tokens=300,
            temperature=0.3
        )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        json_str = response.split("Assistant:")[-1].strip()
        return json.loads(json_str)
    
    except Exception as e:
        print(f"⚠️ Error for {cve_id}: {str(e)[:100]}...")
        return {"classes": [], "relations": [], "axioms": []}

# --- Batch Processor --- (Same as before)
def run_batch():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)[:MAX_CVES]
    
    tokenizer, model = load_model()
    output = []
    
    print(f"🔍 Processing {len(records)} CVEs...")
    for i, item in enumerate(records, 1):
        print(f"[{i}/{len(records)}] CVE: {item['id']}")
        output.append({
            "id": item["id"],
            "prompt_input": item["prompt_input"],
            "llm_output": call_llm(item["prompt_input"], item["id"], tokenizer, model)
        })
        sleep(1)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"💾 Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    run_batch()
