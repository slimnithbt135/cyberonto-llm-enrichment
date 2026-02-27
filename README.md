Markdown
Copy
Code
Preview
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
---
What It Does
Input (from data/cve_2023_preprocessed.json):
"SQL injection vulnerability in Apache Struts 2.3 allows authentication bypass..."
Output (to output/results.json):
JSON
Copy
{
  "cve_id": "CVE-2023-XXXX",
  "classes": ["SQLInjection", "ApacheStruts", "AuthenticationBypass"],
  "relations": [{"subject": "SQLInjection", "predicate": "affects", "object": "ApacheStruts"}],
  "axioms": ["SQLInjection ⊑ InjectionAttack"]
}
Repository Layout
Table
Copy
Directory	Contents
src/	Core extraction logic (extractor.py, patterns_data.py)
scripts/	Legacy processors and converters
evaluation/	Benchmarking scripts vs. LLMs
data/	Input CVEs and ground truth annotations
output/	Generated JSON, TTL, OWL files
queries/	SPARQL queries for ontology validation
patterns/	Rule definitions (editable)
Key Files
run_extractor.py — Main entry point
convert_to_owl.py — RDF/OWL serialization
Makefile — Automates the workflow
requirements.txt — Dependencies (rdflib, pandas, no PyTorch)
Why Patterns Beat LLMs (For This)
Tested on 151 CVEs with official NVD mappings:
Table
Copy
Metric	CyberRule	Llama 3.3 70B
Precision	42.3%	4.2%
F1-Score	0.387	0.067
Entities/CVE	2.1	20+ (hallucinated)
Deterministic?	Yes	No
The LLM generated plausible-sounding vulnerabilities that weren't in the descriptions. CyberRule extracts only what's there—traceable to specific regex patterns.
Configuration
Edit src/cyberrule/patterns_data.py to add rules:
Python
Copy
VULN_PATTERNS = {
    r'\bSQL\s+injection\b': 'SQLInjection',
    r'\bbuffer\s+overflow\b': 'BufferOverflow',
    # Add your own...
}
Or adjust MAX_CVES in run_extractor.py (default: 2000).
Requirements
Python 3.8+
No GPU needed
No API keys
Runs offline
Testing
bash
Copy
make test
Runs unit tests on load_data.py and run_extractor.py to verify basic functionality before full execution.
Output Formats
The pipeline generates three file types in output/:
Table
Copy
Extension	Description	Tool
.json	Structured extraction results	CyberRule engine
.ttl	Turtle format RDF triples	convert_to_owl.py
.owl	OWL-DL ontology (HermiT-validated)	convert_to_owl.py
Cleaning Up
bash
Copy
make clean
Removes all generated files and Python cache directories.
Troubleshooting
Issue: ModuleNotFoundError: No module named 'cyberrule'
Fix: Run make install or pip install -e . first
Issue: Missing input file
Fix: Ensure data/cve_2023_preprocessed.json exists (generate via scripts/legacy/preprocess_cve_data.py if needed)
Issue: Permission denied on make
Fix: Use python run_extractor.py directly; Makefile is optional convenience
Development Notes
Patterns are prioritized by tier: VulnerabilityType (100) > Product (90) > Component (80)
Longer regex matches win ties within same tier
All extractions include provenance tracking (which pattern matched)
Citation
bibtex
Copy
@article{slimani2024cyberrule,
  title={CyberRule: A Deterministic Rule-Based Framework for Reproducible Cybersecurity Ontology Enrichment},
  author={Slimani, Thabet},
  year={2024}
}
License
MIT. See paper for limitations (18% CWE coverage, no syntactic parsing).
Contact
Thabet Slimani — thabet.slimani@gmail.com
For bug reports, include CVE IDs that fail extraction and expected vs. actual output.
