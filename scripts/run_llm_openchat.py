import requests
import gzip
import json
import os

def download_and_extract_feed(year="2023", out_file="data/cve_2023_sample.json"):
    url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
    local_gz = f"data/nvdcve-{year}.json.gz"
    local_json = f"data/nvdcve-{year}.json"

    # Create data directory if needed
    os.makedirs("data", exist_ok=True)

    # Download
    print(f"Downloading {url}...")
    r = requests.get(url, stream=True)
    with open(local_gz, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    print(f"Saved {local_gz}")

    # Extract
    print("Extracting JSON...")
    with gzip.open(local_gz, 'rb') as f_in:
        with open(local_json, 'wb') as f_out:
            f_out.write(f_in.read())
    print(f"Extracted to {local_json}")

    # Read and filter
    with open(local_json, "r", encoding="utf-8") as f:
        raw = json.load(f)
    
    entries = raw.get("CVE_Items", [])
    simplified = []
    for item in entries[:2000]:  # Limit to 2000
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        descs = item["cve"]["description"]["description_data"]
        description = next((d["value"] for d in descs if d["lang"] == "en"), "")
        simplified.append({
            "id": cve_id,
            "description": description
        })

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(simplified, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(simplified)} CVE descriptions to {out_file}")

if __name__ == "__main__":
    download_and_extract_feed()
