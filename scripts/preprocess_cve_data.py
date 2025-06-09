import json
import os
import re

def clean_text(text):
    # Basic normalization: lowercase, strip, remove extra whitespace
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text

def generate_prompt(description):
    return f"Extract cybersecurity concepts and relationships from the following description:\n\n{description}"

def preprocess_cve_file(infile="data/cve_2023_sample.json", outfile="data/cve_2023_preprocessed.json"):
    if not os.path.exists(infile):
        raise FileNotFoundError(f"Input file {infile} not found.")

    with open(infile, "r", encoding="utf-8") as f:
        cve_data = json.load(f)

    processed = []
    for entry in cve_data:
        desc = clean_text(entry["description"])
        prompt = generate_prompt(desc)
        processed.append({
            "id": entry["id"],
            "description": desc,
            "prompt_input": prompt
        })

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(processed, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(processed)} preprocessed CVEs to {outfile}")

if __name__ == "__main__":
    preprocess_cve_file()
