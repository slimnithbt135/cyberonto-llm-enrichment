#!/usr/bin/env python3
"""
CyberRule Extractor Runner
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import sys
import os
import json
import argparse
from pathlib import Path
from time import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cyberrule import CyberRuleExtractor


def main():
    parser = argparse.ArgumentParser(description='CyberRule CVE Extractor')
    parser.add_argument('--input', '-i', help='Input JSON file with CVEs')
    parser.add_argument('--output', '-o', default='output/extraction_results.json', help='Output file')
    parser.add_argument('--max', '-m', type=int, default=2000, help='Max CVEs to process')
    parser.add_argument('--test', '-t', action='store_true', help='Run test mode')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("CyberRule: Deterministic Rule-Based CVE Extraction")
    print("Author: Thabet Slimani <thabet.slimani@gmail.com>")
    print("=" * 70)
    
    # Initialize
    print("\n[1/3] Initializing extractor...")
    extractor = CyberRuleExtractor.from_hardcoded()
    stats = extractor.get_statistics()
    print(f"      ✓ Loaded {stats['total_patterns']} patterns")
    print(f"        Categories: {', '.join(stats['patterns_by_category'].keys())}")
    
    # Test mode
    if args.test or not args.input:
        print("\n[2/3] TEST MODE - Sample extraction")
        test_desc = "SQL injection vulnerability in Apache Tomcat 8.5 allows remote attackers to execute arbitrary code via the admin panel"
        result = extractor.extract("CVE-2023-TEST-001", test_desc)
        
        print(f"\n      Input: {test_desc[:60]}...")
        print(f"\n      Extracted Classes ({len(result['classes'])}):")
        for cls in result['classes']:
            print(f"        - {cls}")
        
        print(f"\n      Extracted Relations ({len(result['relations'])}):")
        for rel in result['relations']:
            print(f"        - {rel['subject']} → {rel['predicate']} → {rel['object']}")
        
        if result['axioms']:
            print(f"\n      Generated Axioms ({len(result['axioms'])}):")
            for axiom in result['axioms']:
                print(f"        - {axiom}")
        
        print("\n[3/3] Test completed successfully!")
        print("=" * 70)
        return
    
    # File processing mode
    print(f"\n[2/3] Processing: {args.input}")
    
    if not os.path.exists(args.input):
        print(f"      ✗ ERROR: File not found: {args.input}")
        return
    
    with open(args.input, 'r', encoding='utf-8') as f:
        records = json.load(f)[:args.max]
    
    print(f"      Found {len(records)} CVEs (max: {args.max})")
    
    results = []
    start_time = time()
    
    for i, item in enumerate(records, 1):
        desc = item.get('description', item.get('prompt_input', ''))
        extracted = extractor.extract(item['id'], desc)
        
        results.append({
            "id": item["id"],
            "prompt_input": desc,
            "llm_output": extracted
        })
        
        if i % 100 == 0 or i == len(records):
            elapsed = time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"      Progress: {i}/{len(records)} ({rate:.1f} CVEs/sec)")
    
    # Save results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Statistics
    total_classes = sum(len(r['llm_output']['classes']) for r in results)
    total_relations = sum(len(r['llm_output']['relations']) for r in results)
    total_time = time() - start_time
    
    print(f"\n[3/3] Results saved to: {args.output}")
    print(f"      Processing time: {total_time:.2f} seconds")
    print(f"      Total CVEs: {len(results)}")
    print(f"      CVEs with extractions: {sum(1 for r in results if r['llm_output']['classes'])}")
    print(f"      Total classes: {total_classes}")
    print(f"      Total relations: {total_relations}")
    print(f"      Avg classes/CVE: {total_classes/len(results):.2f}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
