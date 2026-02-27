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

{
  "cve_id": "CVE-2023-XXXX",
  "classes": ["SQLInjection", "ApacheStruts", "AuthenticationBypass"],
  "relations": [{"subject": "SQLInjection", "predicate": "affects", "object": "ApacheStruts"}],
  "axioms": ["SQLInjection ⊑ InjectionAttack"]
}

## **Repository Layout**

| Directory     | Contents                                                   |
| ------------- | ---------------------------------------------------------- |
| `src/`        | Core extraction logic (`extractor.py`, `patterns_data.py`) |
| `scripts/`    | Legacy processors and converters                           |
| `evaluation/` | Benchmarking scripts vs. LLMs                              |
| `data/`       | Input CVEs and ground truth annotations                    |
| `output/`     | Generated JSON, TTL, OWL files                             |
| `queries/`    | SPARQL queries for ontology validation                     |
| `patterns/`   | Rule definitions (editable)                                |

