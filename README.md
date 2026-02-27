# CyberRule: Deterministic CVE Ontology Enrichment

A rule-based extraction engine that turns CVE descriptions into structured OWL classes and relations. Built after I spent three weeks debugging why GPT-4 results wouldn't replicate—same code, same prompts, different outputs. CyberRule does the opposite: same input, same output, every time.



## **Quick Start**

```bash
# Install
pip install -e .

# Run full pipeline
make full

# Or step by step
make run      # Extract from CVEs
make analyze  # Evaluate results  
make convert  # Generate OWL/TTL
**What It Does**
Input (from data/cve_2023_preprocessed.json):
"SQL injection vulnerability in Apache Struts 2.3 allows authentication bypass..."
Output (to output/results.json):
