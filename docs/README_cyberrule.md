# 📘 CyberRule: Pattern-Based Ontology Enrichment Engine

**CyberRule** is a lightweight, rule-based enrichment module for extracting cybersecurity concepts, relationships, and logical axioms from textual vulnerability data such as CVE descriptions.

Unlike LLM-based enrichment that depends on cloud APIs, CyberRule performs **fully deterministic extraction** using curated regular expressions and taxonomies inspired by standards like **CWE**, **CVE**, and **MITRE ATT&CK**. It enables reproducible and transparent enrichment for ontology-driven threat intelligence.

---

## ✅ Features

- **Offline**: No internet connection or API key required
- **Interpretable**: All extracted entities and triples trace back to specific rules
- **Extensible**: Rules defined in editable Python dictionaries (e.g., `VULN_PATTERNS`, `PRODUCT_PATTERNS`)
- **Reproducible**: Outputs are deterministic and suitable for academic evaluation

---

## 📁 Input / Output

| File                               | Description                                    |
|------------------------------------|------------------------------------------------|
| `data/cve_2023_preprocessed.json` | Input file with raw or cleaned CVE text        |
| `data/cve_2023_enriched.json`     | Output file with enriched classes, relations, axioms |

Each output entry has the structure:
```json
{
  "id": "CVE-2023-XXXX",
  "prompt_input": "...",
  "llm_output": {
    "classes": ["SQLInjection", "Apache"],
    "relations": [
      {"subject": "SQLInjection", "predicate": "affects", "object": "Database"}
    ],
    "axioms": [
      "SQLInjection ⊑ InjectionAttack"
    ]
  }
}
```

---

## 🚀 Run the Script

```bash
cd scripts/
python cyberrule_enricher.py
```

> Ensure that `data/cve_2023_preprocessed.json` exists in the `data/` directory.

---

## 🔧 Configuration

You can adjust the number of processed CVEs:
```python
MAX_CVES = 2000
```

Or extend the logic by editing the rule sets:
```python
VULN_PATTERNS = {
    r'\bSQL injection\b': 'SQLInjection',
    ...
}
```

---

## 📚 Suggested Use Cases

- Testing RDF/OWL conversion pipelines
- Validating semantic enrichment tools
- Benchmarking against LLM-based extraction
- Use in educational or constrained-compute settings