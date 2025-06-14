
## 🔍 Evaluation Script: `analyze_enriched_output.py`

The `analyze_enriched_output.py` script provides a lightweight utility to evaluate the output of the CyberRule enrichment process. It parses the file `data/cve_2023_enriched.json` and computes statistics that can be used to report coverage, output density, and quality in research papers or benchmarks.

### 📂 File Location
```
scripts/analyze_enriched_output.py
```

### 🧪 What It Does
- Counts total number of CVEs processed.
- Computes:
  - Total number of unique OWL classes extracted.
  - Number of RDF-style object properties (relations).
  - Number of logical axioms.
  - Total RDF-style triples.
  - Number of CVEs with no extracted output (empty enrichment).

### 🏁 How to Run

```bash
python scripts/analyze_enriched_output.py
```

> ⚠️ Make sure the file `data/cve_2023_enriched.json` exists and contains the output from the CyberRule enrichment step.

### ✅ Example Output

```
=== CyberRule Enrichment Statistics ===
📄 Total CVE Entries         : 2000
📚 Total Unique Classes      : 517
🔗 Total Object Properties   : 1424
🧠 Total Logical Axioms      : 800
🔢 Total RDF-like Triples    : 6766
🚫 Empty Enrichment Entries  : 390
```

### 📘 Purpose

This script is designed for **transparent, reproducible evaluation** of the semantic enrichment process. It is referenced in:

> Section 5.1 – *Quantitative Evaluation of Semantic Output* in the accompanying research paper.
