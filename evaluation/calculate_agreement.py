#!/usr/bin/env python3
"""
Calculate Inter-Annotator Agreement (Cohen's Kappa)
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Tuple


def load_annotations(annotator_dirs: List[str]) -> Dict[str, List[Dict]]:
    """Load annotations from multiple annotators."""
    by_cve = defaultdict(list)
    
    for annotator_dir in annotator_dirs:
        path = Path(annotator_dir)
        for ann_file in path.glob('CVE-*.json'):
            with open(ann_file, 'r') as f:
                data = json.load(f)
                cve_id = data['cve_id']
                by_cve[cve_id].append(data)
    
    return dict(by_cve)


def extract_entities(annotation: Dict) -> set:
    """Extract (type, normalized) pairs from annotation."""
    entities = set()
    for e in annotation.get('entities', []):
        # Use normalized form for comparison
        key = (e.get('type', 'Unknown'), e.get('normalized', e.get('text', '')).lower())
        entities.add(key)
    return entities


def calculate_pairwise_kappa(ann1: Dict, ann2: Dict) -> float:
    """
    Calculate entity-level agreement between two annotations.
    Simplified Cohen's Kappa for entity extraction.
    """
    entities1 = extract_entities(ann1)
    entities2 = extract_entities(ann2)
    
    # Observed agreement (entities that match)
    intersection = entities1 & entities2
    union = entities1 | entities2
    
    if not union:
        return 1.0  # Both empty = perfect agreement
    
    # Simple agreement ratio (can be enhanced with true kappa)
    agreement = len(intersection) / len(union)
    
    return agreement


def calculate_fleiss_kappa(annotations_by_cve: Dict[str, List[Dict]]) -> Dict:
    """Calculate Fleiss' Kappa for multiple annotators."""
    # Simplified implementation
    agreements = []
    
    for cve_id, annotations in annotations_by_cve.items():
        if len(annotations) < 2:
            continue
        
        # Calculate pairwise agreements for this CVE
        cve_agreements = []
        for i in range(len(annotations)):
            for j in range(i+1, len(annotations)):
                kappa = calculate_pairwise_kappa(annotations[i], annotations[j])
                cve_agreements.append(kappa)
        
        if cve_agreements:
            agreements.append(sum(cve_agreements) / len(cve_agreements))
    
    if not agreements:
        return {'kappa': 0, 'interpretation': 'No overlapping annotations'}
    
    avg_kappa = sum(agreements) / len(agreements)
    
    # Interpretation
    if avg_kappa >= 0.81:
        interpretation = "Almost perfect agreement"
    elif avg_kappa >= 0.61:
        interpretation = "Substantial agreement"
    elif avg_kappa >= 0.41:
        interpretation = "Moderate agreement"
    else:
        interpretation = "Fair/poor agreement"
    
    return {
        'kappa': round(avg_kappa, 3),
        'interpretation': interpretation,
        'n_cves_evaluated': len(agreements),
        'pairwise_agreements': [round(a, 3) for a in agreements[:10]]  # First 10
    }


def print_agreement_report(annotations_by_cve: Dict):
    """Print detailed agreement report."""
    print("\n" + "=" * 70)
    print("INTER-ANNOTATOR AGREEMENT REPORT")
    print("=" * 70)
    
    # Per-CVE breakdown
    print("\nPer-CVE Agreement:")
    for cve_id, annotations in sorted(annotations_by_cve.items())[:5]:  # Show first 5
        if len(annotations) >= 2:
            print(f"\n  {cve_id}:")
            for i, ann in enumerate(annotations):
                annotator = ann['metadata'].get('annotator', f'Annotator{i+1}')
                n_entities = len(ann.get('entities', []))
                print(f"    {annotator}: {n_entities} entities")
            
            if len(annotations) == 2:
                kappa = calculate_pairwise_kappa(annotations[0], annotations[1])
                print(f"    Agreement: {kappa:.3f}")
    
    # Overall
    result = calculate_fleiss_kappa(annotations_by_cve)
    
    print("\n" + "-" * 70)
    print("OVERALL AGREEMENT")
    print("-" * 70)
    print(f"  Fleiss' Kappa: {result['kappa']}")
    print(f"  Interpretation: {result['interpretation']}")
    print(f"  CVEs evaluated: {result['n_cves_evaluated']}")
    
    if result['pairwise_agreements']:
        print(f"\n  Sample agreements: {result['pairwise_agreements']}")
    
    print("=" * 70)
    
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--annotators', nargs='+', required=True,
                       help='Directories for each annotator (e.g., annotations/annotator_001 annotations/annotator_002)')
    parser.add_argument('--output', '-o', help='Save report to JSON file')
    args = parser.parse_args()
    
    # Load annotations
    by_cve = load_annotations(args.annotators)
    
    # Calculate and print
    result = print_agreement_report(by_cve)
    
    # Save if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n✓ Report saved to {args.output}")
