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
```

## **What It Does**
Input (from data/cve_2023_preprocessed.json):     
"SQL injection vulnerability in Apache Struts 2.3 allows authentication bypass..."      
Output (to output/results.json):
```bash
{
  "cve_id": "CVE-2023-XXXX",
  "classes": ["SQLInjection", "ApacheStruts", "AuthenticationBypass"],
  "relations": [{"subject": "SQLInjection", "predicate": "affects", "object": "ApacheStruts"}],
  "axioms": ["SQLInjection ⊑ InjectionAttack"]
}
```

## **Repository Layout**

| Directory     | Contents                                                   |
| ------------- | ---------------------------------------------------------- |
| `src/`        | Core extraction logic (`extractor.py`, `patterns_data.py`) |
| `scripts/`    | Legacy processors and converters                           |
| `evaluation/` | Benchmarking scripts vs. LLMs                              |
| `data/`       | Input CVEs and ground truth annotations                    |
| `outputs/`     | Generated JSON, TTL, OWL files                             |
| `queries/`    | SPARQL queries for ontology validation                     |
| `patterns/`   | Rule definitions (editable)                                |

## **Key Files**

run_extractor.py — Main entry point
convert_to_owl.py — RDF/OWL serialization
Makefile — Automates the workflow
requirements.txt — Dependencies (rdflib, pandas, no PyTorch)

## **Why Patterns Beat LLMs (For This)**
Tested on 151 CVEs with official NVD mappings:
| Metric         | CyberRule | Llama 3.3 70B      |
| -------------- | --------- | ------------------ |
| Precision      | 42.3%     | 4.2%               |
| F1-Score       | 0.387     | 0.067              |
| Entities/CVE   | 2.1       | 20+ (hallucinated) |
| Deterministic? | Yes       | No                 |

The LLM generated plausible-sounding vulnerabilities that weren't in the descriptions. CyberRule extracts only what's there—traceable to specific regex patterns.

## **Configuration**
Edit src/cyberrule/patterns_data.py to add rules:
```bash
VULN_PATTERNS = {
    r'\bSQL\s+injection\b': 'SQLInjection',
    r'\bbuffer\s+overflow\b': 'BufferOverflow',
    # Add your own...
}
```
