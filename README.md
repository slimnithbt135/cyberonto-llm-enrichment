
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

---

## **Legacy Scripts (`scripts/legacy/`)**

These scripts were developed during the initial research phase (late 2025). Some are one-off utilities, others are superseded by the refactored `src/` package. Kept for reproducibility—the paper's Table 1 used `CyberRule-Enricher.py` v1.2, not the current extractor.

| Script | What It Actually Does | Status |
|--------|----------------------|--------|
| `CyberRule-Enricher.py` | Original monolithic extractor with 60+ regex patterns hardcoded across 4 dictionaries (VULN_PATTERNS, PRODUCT_PATTERNS, COMPONENT_TYPES, PRIVILEGE_PATTERNS). Version-aware product extraction (e.g., "Apache_v2.4"). | **Superseded** by `src/cyberrule/extractor.py` |
| `generate_rdf_from_cyberrule.py` | Converts JSON enrichment output to Turtle RDF. Uses hardcoded namespace `http://example.org/ontology#`. Serializes classes, relations, and axioms as triples. | **Active** — used by `make convert` |
| `convert_ttl_to_owl.py` | Simple rdflib wrapper: parses Turtle, serializes to OWL/XML. No reasoning, no validation. One-way format conversion. | **Deprecated** — use `convert_to_owl.py` (HermiT-validated) |
| `sparql_query_example.py` | Demo script. Runs hardcoded query: `?vuln :affects ?component` with LIMIT 10. Shows basic rdflib SPARQL usage. | Documentation only |
| `sparql_admin_privileges.py` | Slightly modified demo. Queries for `?vuln :requires :Administrator`. Used to verify privilege extraction worked. | Documentation only |

---

### **Why These Are "Legacy"**

The refactored `src/cyberrule/` package separates concerns: `extractor.py` for patterns, `owl_export.py` for reasoning, `load_data.py` for I/O. These monolithic scripts do everything in one file. They work, but they're harder to test and extend.

That said, `generate_rdf_from_cyberrule.py` is still used in the current pipeline—it reliably converts the JSON structure to valid Turtle without the overhead of HermiT reasoning.

---

### **Pattern Coverage in `CyberRule-Enricher.py`**

The original extractor contains 60+ hand-crafted regex patterns across four categories:

| Dictionary | Count | Example Pattern | Example Output |
|------------|-------|-----------------|--------------|
| `VULN_PATTERNS` | ~30 | `r'\bSQLi?\b\|\bSQL injection\b'` | `SQLInjection` |
| `PRODUCT_PATTERNS` | ~25 | `r'\bPalo Alto Networks\b\|\bPAN-OS\b'` | `PaloAlto_PAN-OS` |
| `COMPONENT_TYPES` | ~20 | `r'\bweb interface\b'` | `WebInterface` |
| `PRIVILEGE_PATTERNS` | ~15 | `r'\badmin\b\|\badministrator\b'` | `Administrator` |

Special handling:
- **Version extraction**: Products get version suffixes (`Apache_v2.4`) via regex `(\d+\.\d+(\.\d+)?(\w+)?)`
- **Axiom generation**: Hardcoded subclass axioms like `SQLInjection ⊑ DatabaseAttack`
- **Relation building**: Auto-generates `(vuln, affects, component)` and `(vuln, requires, privilege)` triples

---

### **SPARQL Query Examples**

The `queries/` directory (if populated) would contain `.sparql` files. These scripts show the query patterns used:

**Find vulnerabilities affecting web interfaces:**
```sparql
PREFIX : &lt;http://example.org/ontology#&gt;
SELECT ?vuln ?component
WHERE {
  ?vuln :affects ?component .
}
```
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
Or adjust MAX_CVES in run_extractor.py (default: 2000).
## **Requirements**
Python 3.8+
No GPU needed
No API keys
Runs offline

## **Testing**
```bash
make test
```
Runs unit tests on load_data.py and run_extractor.py to verify basic functionality before full execution.
## **Output Formats**
The pipeline generates three file types in output/:
| Extension | Description                        | Tool                |
| --------- | ---------------------------------- | ------------------- |
| `.json`   | Structured extraction results      | CyberRule engine    |
| `.ttl`    | Turtle format RDF triples          | `convert_to_owl.py` |
| `.owl`    | OWL-DL ontology (HermiT-validated) | `convert_to_owl.py` |
## **Cleaning Up**
```bash
make clean
```
## **Troubleshooting**
Issue: ModuleNotFoundError: No module named 'cyberrule'
Fix: Run make install or pip install -e . first
Issue: Missing input file
Fix: Ensure data/cve_2023_preprocessed.json exists (generate via scripts/legacy/preprocess_cve_data.py if needed)
Issue: Permission denied on make
Fix: Use python run_extractor.py directly; Makefile is optional convenience
## **Development Notes**

Patterns are prioritized by tier: VulnerabilityType (100) > Product (90) > Component (80)
Longer regex matches win ties within same tier
All extractions include provenance tracking (which pattern matched)


## **Evaluation Scripts (`evaluation/`)**

These scripts benchmark CyberRule against ground truth and compare with LLM baselines. They generated the numbers in our paper (Table 1, Table 2).

| Script | Purpose | Key Output |
|--------|---------|------------|
| `evaluate_cyberrule.py` | Main evaluation against NVD reference standard. Calculates precision/recall/F1 with fuzzy matching for normalization variants (e.g., "SQLInjection" vs "SqlInjection"). | `cyberrule_evaluation_fixed.json` |
| `evaluate_baseline.py` | Simple keyword baseline for comparison. No regex, no context—just string membership. Shows what "dumb" matching achieves. | `baseline_evaluation.json` |
| `evaluate_groq.py` | Llama 3.3 70B evaluation via Groq API. Runs 3 times per CVE to measure variance. Requires `GROQ_API_KEY` env var. | `llama3_evaluation.json` |
| `evaluate_groq_standalone.py` | Same as above but fully self-contained. No imports from CyberRule. Use this if you only want to test the LLM without installing our package. | Same |
| `create_reference_standard.py` | Builds ground truth from official NVD CWE mappings. Stratified sampling by severity. Hits NVD API with rate limiting (0.6s delay). | `reference_standard_200.json` |
| `calculate_agreement.py` | Inter-annotator agreement (Cohen's Kappa). Used when multiple humans annotated the same CVEs to measure label quality. | Agreement report |
| `cross_validate.py` | 5-fold stratified cross-validation. Tests extractor stability across different CVE subsets. Reports confidence intervals. | CV metrics with 95% CI |
| `analyze_output.py` | Descriptive statistics on extraction results. Class frequency, relation distribution, empty entry count. | Console report |
| `generate_paper_tables.py` | Converts JSON results to LaTeX tables and suggested paper text. Includes per-category breakdowns. | `paper_text_snippets.txt` |


### **Typical Evaluation Workflow**

```bash
# 1. Create reference standard (run once, slow due to API calls)
python evaluation/create_reference_standard.py

# 2. Evaluate CyberRule
python evaluation/evaluate_cyberrule.py

# 3. Evaluate baseline for comparison
python evaluation/evaluate_baseline.py

# 4. Evaluate Llama 3.3 (requires API key)
export GROQ_API_KEY="gsk_..."
python evaluation/evaluate_groq.py --max 100

## **License**
MIT. See paper for limitations (18% CWE coverage, no syntactic parsing).

