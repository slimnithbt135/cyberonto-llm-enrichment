#!/usr/bin/env python3
"""
Evaluate CyberRule against reference standard - FIXED VERSION.
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import List, Set, Tuple
import re

# Setup paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cyberrule.extractor import CyberRuleExtractor


def normalize_class_name(name: str) -> str:
    """Normalize class name to match extractor output conventions."""
    # Apply same logic as extractor's _normalize_value
    name = re.sub(r'[^a-zA-Z0-9]', '', name)
    
    # Handle acronyms per CWE conventions
    cwe_naming_map = {
        'sql': 'Sql',
        'sqli': 'Sql',
        'xss': 'Xss',
        'csrf': 'Csrf',
        'xxe': 'Xxe',
        'ssrf': 'Ssrf',
        'rce': 'Rce',
        'dos': 'Dos',
        'ldap': 'Ldap',
        'xpath': 'Xpath',
        'html': 'Html',
        'xml': 'Xml',
        'json': 'Json',
        'jwt': 'Jwt',
        'oauth': 'Oauth',
        'saml': 'Saml'
    }
    
    name_lower = name.lower()
    
    # Check for direct match in map
    if name_lower in cwe_naming_map:
        return cwe_naming_map[name_lower] + 'Injection' if 'injection' in name_lower else cwe_naming_map[name_lower]
    
    # Split camelCase and normalize
    words = re.split(r'(?=[A-Z])', name)
    words = [w for w in words if w]
    
    normalized = []
    for word in words:
        word_lower = word.lower()
        if word_lower in cwe_naming_map:
            normalized.append(cwe_naming_map[word_lower])
        else:
            normalized.append(word.capitalize())
    
    return ''.join(normalized)


def calculate_metrics(predicted: Set[str], actual: Set[str]) -> dict:
    """Calculate metrics with fuzzy matching."""
    
    # Normalize both sets
    pred_norm = {normalize_class_name(p): p for p in predicted}
    actual_norm = {normalize_class_name(a): a for a in actual}
    
    # Find matches
    matches = set(pred_norm.keys()) & set(actual_norm.keys())
    
    tp = len(matches)
    fp = len(predicted) - len(matches)
    fn = len(actual) - len(matches)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'matches': list(matches),
        'predicted_normalized': list(pred_norm.keys()),
        'actual_normalized': list(actual_norm.keys())
    }


def evaluate_cyberrule(reference_file: str, output_file: str):
    """Evaluate CyberRule extraction against reference standard."""
    
    reference_path = PROJECT_ROOT / reference_file
    output_path = PROJECT_ROOT / output_file
    
    with open(reference_path, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    extractor = CyberRuleExtractor.from_hardcoded()
    
    results = []
    all_predicted = []
    all_actual = []
    
    print("Evaluating CyberRule against reference standard...")
    print("=" * 70)
    
    for i, ref in enumerate(reference):
        cve_id = ref['cve_id']
        description = ref['description']
        
        extraction = extractor.extract(cve_id, description)
        predicted_classes = set(extraction['classes'])
        
        actual_classes = set(ref.get('ground_truth_classes', []))
        
        metrics = calculate_metrics(predicted_classes, actual_classes)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(predicted_classes),
            'actual': list(actual_classes),
            'metrics': metrics
        })
        
        all_predicted.extend(predicted_classes)
        all_actual.extend(actual_classes)
        
        if (i + 1) % 50 == 0:
            print(f"Processed {i+1}/{len(reference)} CVEs...")
    
    # Overall metrics
    overall = calculate_metrics(set(all_predicted), set(all_actual))
    
    # Per-category analysis
    category_metrics = analyze_by_category(results)
    
    summary = {
        'total_cves': len(reference),
        'overall_metrics': overall,
        'category_metrics': category_metrics,
        'per_cve_results': results
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)
    print(f"Total CVEs evaluated: {len(reference)}")
    print(f"Overall Precision: {overall['precision']:.3f}")
    print(f"Overall Recall:    {overall['recall']:.3f}")
    print(f"Overall F1-Score:  {overall['f1']:.3f}")
    print(f"\nTrue Positives:  {overall['tp']}")
    print(f"False Positives: {overall['fp']}")
    print(f"False Negatives: {overall['fn']}")
    print(f"\nCategory Breakdown:")
    for cat, metrics in category_metrics.items():
        print(f"  {cat}: F1={metrics['f1']:.3f}, Support={metrics['support']}")
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


def analyze_by_category(results: List[dict]) -> dict:
    """Analyze metrics by vulnerability category."""
    
    categories = {
        'injection': ['sqlinjection', 'commandinjection', 'codeinjection', 'xpathinjection', 'ldapinjection'],
        'xss': ['crosssitescripting', 'xss', 'storedxss', 'reflectedxss'],
        'overflow': ['bufferoverflow', 'stackoverflow', 'heapoverflow', 'integeroverflow'],
        'authentication': ['authenticationbypass', 'weakauthentication', 'missingauthentication', 'brokenauthentication'],
        'authorization': ['incorrectauthorization', 'missingauthorization', 'privilegeescalation', 'privesc'],
        'information_disclosure': ['informationdisclosure', 'dataexposure', 'sensitivedataexposure', 'informationleak'],
        'traversal': ['pathtraversal', 'directorytraversal'],
        'dos': ['denialofservice', 'dos', 'uncontrolledresourceconsumption'],
        'csrf': ['crosssiterequestforgery', 'csrf'],
        'xxe': ['xmlexternalentity', 'xxe'],
        'ssrf': ['serversiderequestforgery', 'ssrf'],
        'deserialization': ['deserializationofuntrusteddata', 'insecuredeserialization'],
        'credentials': ['useofhardcodedcredentials', 'hardcodedpassword', 'defaultcredentials'],
        'products': ['microsoft', 'apache', 'oracle', 'adobe', 'cisco', 'nginx', 'linux', 'windows']
    }
    
    category_metrics = {}
    
    for cat_name, patterns in categories.items():
        cat_tp = cat_fp = cat_fn = 0
        
        for r in results:
            pred_norm = set(r['metrics']['predicted_normalized'])
            actual_norm = set(r['metrics']['actual_normalized'])
            
            pred_in_cat = any(p in ' '.join(patterns) for p in pred_norm)
            actual_in_cat = any(a in ' '.join(patterns) for a in actual_norm)
            
            if actual_in_cat:
                # Check for specific match
                matched = bool(set(p for p in pred_norm if any(pat in p for pat in patterns)) & 
                              set(a for a in actual_norm if any(pat in a for pat in patterns)))
                if matched:
                    cat_tp += 1
                else:
                    cat_fn += 1
            elif pred_in_cat:
                cat_fp += 1
        
        if (cat_tp + cat_fp) > 0 and (cat_tp + cat_fn) > 0:
            prec = cat_tp / (cat_tp + cat_fp)
            rec = cat_tp / (cat_tp + cat_fn)
            f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
            
            category_metrics[cat_name] = {
                'precision': round(prec, 3),
                'recall': round(rec, 3),
                'f1': round(f1, 3),
                'tp': cat_tp,
                'fp': cat_fp,
                'fn': cat_fn,
                'support': cat_tp + cat_fn
            }
    
    return category_metrics


if __name__ == '__main__':
    evaluate_cyberrule(
        'evaluation/reference_standard_200.json',
        'evaluation/cyberrule_evaluation_fixed.json'
    )
