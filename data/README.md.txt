# CyberOnto LLM Enrichment

This repository supports a research project on enriching cybersecurity ontologies using Large Language Models (LLMs). It includes scripts, datasets, and evaluation pipelines.

## Step 1: CVE Data Collection

We use NVD's official feed to fetch 2023 CVE reports.

### Script
- `data/fetch_cve_data_from_feed.py`

### Output
- `data/cve_2023_sample.json` — 2,000 cleaned CVE descriptions

---

Future steps will include preprocessing, LLM prompting, and ontology integration.
