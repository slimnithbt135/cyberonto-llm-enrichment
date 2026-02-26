#!/usr/bin/env python3
"""
Standalone Llama 3 evaluation - no CyberRule import needed.
Updated for current Groq models (January 2025).
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import os
import re
import time
from pathlib import Path
from typing import List, Set


def normalize_for_comparison(text: str) -> str:
    """Normalize text for fuzzy matching."""
    text = re.sub(r'[^a-zA-Z0-9]', '', text.lower())
    
    equivalences = {
        'sql': 'sql', 'sqli': 'sqlinjection',
        'xss': 'crosssitescripting',
        'csrf': 'crosssiterequestforgery',
        'xxe': 'xmlexternalentity',
        'ssrf': 'serversiderequestforgery',
        'rce': 'remotecodeexecution',
        'dos': 'denialofservice',
    }
    
    for key, val in equivalences.items():
        if key in text:
            return val
    
    return text


def calculate_metrics(predicted: Set[str], actual: Set[str]) -> dict:
    """Calculate metrics with fuzzy matching."""
    pred_norm = {normalize_for_comparison(p): p for p in predicted}
    actual_norm = {normalize_for_comparison(a): a for a in actual}
    
    matches = set(pred_norm.keys()) & set(actual_norm.keys())
    
    tp = len(matches)
    fp = len(predicted) - tp
    fn = len(actual) - len(matches)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'tp': tp, 'fp': fp, 'fn': fn
    }


def extract_with_llama3(cve_id: str, description: str, api_key: str) -> List[str]:
    """Extract classes using Llama 3.3 via Groq API."""
    
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        
        # Current working model as of January 2025
        MODEL = "llama-3.3-70b-versatile"
        
        prompt = f"""You are a cybersecurity ontology extraction system.

CVE ID: {cve_id}
Description: {description}

Extract entity classes from this CVE description. Return ONLY a JSON array of CamelCase class names.

Entity types to extract:
- VulnerabilityType (e.g., SQLInjection, BufferOverflow, CrossSiteScripting, PathTraversal)
- AffectedProduct (e.g., Microsoft, Apache, Linux, Windows, Oracle)
- AttackVector (Network, Local, Physical)
- Impact (CodeExecution, InformationDisclosure, DenialOfService)

Rules:
- Use CamelCase format
- Be specific (e.g., "SQLInjection" not just "Injection")
- Include product versions if mentioned

Return format: ["ClassName1", "ClassName2", "ClassName3"]
Only the JSON array. No explanation."""

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You extract cybersecurity entities. Return only valid JSON arrays."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=300
        )
        
        content = response.choices[0].message.content
        
        # Parse JSON - handle various formats
        try:
            # Try to find JSON array in response
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                data = json.loads(match.group())
                if isinstance(data, list):
                    return [c for c in data if isinstance(c, str)]
        except:
            pass
        
        # Fallback: extract quoted strings
        matches = re.findall(r'"([^"]+)"', content)
        return [m for m in matches if m and m[0].isupper()]
        
    except Exception as e:
        error_msg = str(e)
        if "decommissioned" in error_msg:
            print(f"Model error - check available models", end=" ")
        else:
            print(f"Error: {error_msg[:80]}", end=" ")
        return []


def evaluate_llama3(reference_file: str, output_file: str, api_key: str, max_cves: int = 100):
    """Evaluate Llama 3 extraction."""
    
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    reference_path = project_root / reference_file
    output_path = project_root / output_file
    
    with open(reference_path, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    subset = reference[:max_cves]
    
    print(f"Evaluating Llama 3.3 on {len(subset)} CVEs...")
    print("Using Groq API - free tier: 1M tokens/day")
    print("=" * 70)
    
    results = []
    
    for i, ref in enumerate(subset):
        cve_id = ref['cve_id']
        description = ref['description']
        
        print(f"[{i+1}/{len(subset)}] {cve_id}...", end=" ", flush=True)
        
        predicted = set(extract_with_llama3(cve_id, description, api_key))
        actual = set(ref.get('ground_truth_classes', []))
        
        metrics = calculate_metrics(predicted, actual)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(predicted),
            'actual': list(actual),
            'metrics': metrics
        })
        
        print(f"Found {len(predicted)} entities, F1={metrics['f1']:.3f}")
        time.sleep(0.2)
    
    # Aggregate metrics
    all_pred = set()
    all_actual = set()
    for r in results:
        all_pred.update(r['predicted'])
        all_actual.update(r['actual'])
    
    overall = calculate_metrics(all_pred, all_actual)
    
    summary = {
        'system': 'Llama 3.3 70B (Groq)',
        'model': 'llama-3.3-70b-versatile',
        'total_cves': len(subset),
        'overall_metrics': overall,
        'per_cve_results': results
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("LLAMA 3.3 EVALUATION RESULTS")
    print("=" * 70)
    print(f"CVEs evaluated: {len(subset)}")
    print(f"Precision: {overall['precision']:.3f}")
    print(f"Recall:    {overall['recall']:.3f}")
    print(f"F1-Score:  {overall['f1']:.3f}")
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference', default='evaluation/reference_standard_200.json')
    parser.add_argument('--output', default='evaluation/llama3_evaluation.json')
    parser.add_argument('--max', type=int, default=100)
    args = parser.parse_args()
    
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key:
        print("Error: Set GROQ_API_KEY environment variable")
        print("Get free API key at: https://console.groq.com/keys")
        exit(1)
    
    evaluate_llama3(args.reference, args.output, api_key, args.max)
