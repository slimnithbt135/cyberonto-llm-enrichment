#!/usr/bin/env python3
"""
Evaluate a simple baseline method for comparison (no API needed).
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import re
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent

sys.path.insert(0, str(SCRIPT_DIR))
from evaluate_cyberrule import calculate_metrics, analyze_by_category


def baseline_extract(description: str) -> set:
    """
    Simple baseline: keyword matching without CyberRule's sophistication.
    This simulates a basic string-matching approach.
    """
    desc_lower = description.lower()
    classes = set()
    
    # Simple keyword matching (no regex, no context)
    keywords = {
        'sql': 'SQLInjection',
        'injection': 'Injection',
        'xss': 'CrossSiteScripting',
        'scripting': 'Scripting',
        'buffer': 'BufferOverflow',
        'overflow': 'Overflow',
        'remote': 'RemoteCodeExecution',
        'execution': 'CodeExecution',
        'traversal': 'PathTraversal',
        'denial': 'DenialOfService',
        'service': 'DenialOfService',
        'information': 'InformationDisclosure',
        'disclosure': 'InformationDisclosure',
        'privilege': 'PrivilegeEscalation',
        'escalation': 'PrivilegeEscalation',
        'authentication': 'AuthenticationBypass',
        'bypass': 'Bypass',
        'microsoft': 'Microsoft',
        'windows': 'Windows',
        'linux': 'Linux',
        'apache': 'Apache',
        'oracle': 'Oracle',
    }
    
    for keyword, class_name in keywords.items():
        if keyword in desc_lower:
            classes.add(class_name)
    
    return classes


def evaluate_baseline(reference_file: str, output_file: str):
    """Evaluate baseline method."""
    
    reference_path = PROJECT_ROOT / reference_file
    output_path = PROJECT_ROOT / output_file
    
    with open(reference_path, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    results = []
    all_predicted = []
    all_actual = []
    
    print("Evaluating baseline method...")
    print("=" * 70)
    
    for i, ref in enumerate(reference):
        cve_id = ref['cve_id']
        description = ref['description']
        
        predicted = baseline_extract(description)
        actual = set(ref.get('ground_truth_classes', []))
        
        metrics = calculate_metrics(predicted, actual)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(predicted),
            'actual': list(actual),
            'metrics': metrics
        })
        
        all_predicted.extend(predicted)
        all_actual.extend(actual)
        
        if (i + 1) % 50 == 0:
            print(f"Processed {i+1}/{len(reference)} CVEs...")
    
    overall = calculate_metrics(set(all_predicted), set(all_actual))
    category_metrics = analyze_by_category(results)
    
    summary = {
        'system': 'Baseline (Simple Keywords)',
        'total_cves': len(reference),
        'overall_metrics': overall,
        'category_metrics': category_metrics,
        'per_cve_results': results
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("BASELINE EVALUATION RESULTS")
    print("=" * 70)
    print(f"Total CVEs evaluated: {len(reference)}")
    print(f"Overall Precision: {overall['precision']:.3f}")
    print(f"Overall Recall:    {overall['recall']:.3f}")
    print(f"Overall F1-Score:  {overall['f1']:.3f}")
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


if __name__ == '__main__':
    evaluate_baseline(
        'evaluation/reference_standard_200.json',
        'evaluation/baseline_evaluation.json'
    )
