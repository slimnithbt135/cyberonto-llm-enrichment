#!/usr/bin/env python3
"""
Analyze CyberRule extraction output
Refactored from analyze_enriched_output.py
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def analyze_output(file_path: str):
    """Comprehensive analysis of extraction results."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        records = json.load(f)
    
    total_cves = len(records)
    
    # Basic counts
    unique_classes = set()
    all_relations = []
    all_axioms = []
    empty_entries = 0
    
    # Detailed tracking
    class_counter = Counter()
    relation_type_counter = Counter()
    
    for record in records:
        output = record.get("llm_output", {})
        classes = output.get("classes", [])
        relations = output.get("relations", [])
        axioms = output.get("axioms", [])
        
        if not classes and not relations and not axioms:
            empty_entries += 1
        
        unique_classes.update(classes)
        for cls in classes:
            class_counter[cls] += 1
        
        for rel in relations:
            rel_str = f"{rel.get('subject')} -> {rel.get('predicate')} -> {rel.get('object')}"
            all_relations.append(rel_str)
            relation_type_counter[rel.get('predicate', 'unknown')] += 1
        
        all_axioms.extend(axioms)
    
    # Statistics
    total_relations = len(all_relations)
    total_axioms = len(all_axioms)
    unique_relations = len(set(all_relations))
    
    print("\n" + "=" * 70)
    print("CyberRule Extraction Analysis")
    print("=" * 70)
    print(f"📄 Total CVE Entries          : {total_cves:,}")
    print(f"📚 Total Unique Classes       : {len(unique_classes):,}")
    print(f"🔗 Total Object Properties    : {total_relations:,}")
    print(f"🔗 Unique Relation Types      : {unique_relations:,}")
    print(f"🧠 Total Logical Axioms       : {total_axioms:,}")
    print(f"🔢 Total RDF-like Triples      : {len(unique_classes) + total_relations + total_axioms:,}")
    print(f"🚫 Empty Enrichment Entries   : {empty_entries:,} ({empty_entries/total_cves*100:.1f}%)")
    
    print("\n" + "-" * 70)
    print("Top 10 Most Frequent Classes:")
    print("-" * 70)
    for cls, count in class_counter.most_common(10):
        print(f"  {cls:<30} : {count:>5} ({count/total_cves*100:>5.1f}%)")
    
    print("\n" + "-" * 70)
    print("Relation Type Distribution:")
    print("-" * 70)
    for pred, count in relation_type_counter.most_common():
        print(f"  {pred:<20} : {count:>5}")
    
    print("\n" + "=" * 70)
    
    # Return stats for further use
    return {
        "total_cves": total_cves,
        "unique_classes": len(unique_classes),
        "total_relations": total_relations,
        "total_axioms": total_axioms,
        "empty_entries": empty_entries,
        "top_classes": dict(class_counter.most_common(10))
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', default='output/results.json', help='Input file')
    args = parser.parse_args()
    
    analyze_output(args.input)
