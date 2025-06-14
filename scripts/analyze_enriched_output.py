"""
analyze_enriched_output.py
===========================
This script analyzes the output of the CyberRule semantic enrichment process
stored in cve_2023_enriched.json. It computes basic statistics such as:
- Total number of CVEs processed
- Unique OWL classes extracted
- Number of object properties (relations)
- Number of logical axioms
- Total RDF-like triples
- Number of CVEs with empty enrichment
Usage:
    python scripts/analyze_enriched_output.py
Author: Thabet Slimani
Repository: https://github.com/slimnithbt135/cyberonto-llm-enrichment
License: MIT
Dependencies:
    - Python 3.7+
    - No external libraries required
"""
import json
from collections import Counter
import json
import os
# Full absolute path for GitHub execution
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE = os.path.join(PROJECT_ROOT, "data", "cve_2023_enriched.json")

def analyze_enriched_output(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    total_cves = len(records)
    total_classes = 0
    total_relations = 0
    total_axioms = 0
    empty_entries = 0

    unique_classes = set()
    relation_counter = Counter()

    for record in records:
        output = record.get("llm_output", {})
        classes = output.get("classes", [])
        relations = output.get("relations", [])
        axioms = output.get("axioms", [])

        if not classes and not relations and not axioms:
            empty_entries += 1

        total_classes += len(classes)
        total_relations += len(relations)
        total_axioms += len(axioms)

        unique_classes.update(classes)
        for rel in relations:
            rel_str = f"{rel.get('subject')} -> {rel.get('predicate')} -> {rel.get('object')}"
            relation_counter[rel_str] += 1

    print("\n=== CyberRule Enrichment Statistics ===")
    print(f"📄 Total CVE Entries         : {total_cves}")
    print(f"📚 Total Unique Classes      : {len(unique_classes)}")
    print(f"🔗 Total Object Properties   : {total_relations}")
    print(f"🧠 Total Logical Axioms      : {total_axioms}")
    print(f"🔢 Total RDF-like Triples    : {total_classes + total_relations + total_axioms}")
    print(f"🚫 Empty Enrichment Entries  : {empty_entries}")

if __name__ == "__main__":
    analyze_enriched_output(INPUT_FILE)
