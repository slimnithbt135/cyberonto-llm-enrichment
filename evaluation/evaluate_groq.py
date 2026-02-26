#!/usr/bin/env python3
"""
Evaluate Llama 3 via Groq API against reference standard.
Free tier: 1,000,000 tokens/day at https://groq.com
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import os
import time
from pathlib import Path
from typing import List, Set, Dict
import sys

# Setup paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from evaluate_cyberrule import calculate_metrics, analyze_by_category


def extract_with_llama3(cve_id: str, description: str, api_key: str) -> List[str]:
    """Extract classes using Llama 3 via Groq API."""
    
    try:
        import groq
        
        client = groq.Groq(api_key=api_key)
        
        prompt = f"""You are a cybersecurity ontology extraction system. 
Extract entity classes from this CVE description.
Return ONLY a JSON array of CamelCase class names.

CVE ID: {cve_id}
Description: {description}

Extract these entity types:
- VulnerabilityType (e.g., SQLInjection, BufferOverflow, CrossSiteScripting)
- AffectedProduct (e.g., Microsoft, Apache, Linux)
- AttackVector (Network, Local, Physical)
- Impact (CodeExecution, InformationDisclosure, DenialOfService)

Rules:
- Use CamelCase (e.g., "SQLInjection" not "sql injection")
- Be specific (e.g., "SQLInjection" not just "Injection")
- Include version if mentioned (e.g., "Windows10")

Return format: ["ClassName1", "ClassName2"]
No explanation, only the JSON array."""

        response = client.chat.completions.create(
            model="llama3-70b-8192",  # or "llama3-8b-8192" for faster/cheaper
            messages=[
                {"role": "system", "content": "You extract cybersecurity entities. Return only valid JSON arrays."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low for reproducibility
            max_tokens=200,
            response_format={"type": "json_object"}  # Force JSON output
        )
        
        content = response.choices[0].message.content
        
        # Parse JSON
        import json as jsonlib
        try:
            # Try direct JSON parse
            data = jsonlib.loads(content)
            if isinstance(data, list):
                return [c for c in data if isinstance(c, str)]
            elif isinstance(data, dict) and 'classes' in data:
                return [c for c in data['classes'] if isinstance(c, str)]
            else:
                # Extract any list from response
                for key, value in data.items():
                    if isinstance(value, list):
                        return [c for c in value if isinstance(c, str)]
                return []
        except:
            # Fallback: extract array-like strings
            import re
            matches = re.findall(r'"([^"]+)"', content)
            return [m for m in matches if m[0].isupper()]  # CamelCase filter
            
    except Exception as e:
        print(f"Error with Llama 3 for {cve_id}: {e}")
        return []


def evaluate_llama3(reference_file: str, output_file: str, api_key: str, max_cves: int = 100):
    """Evaluate Llama 3 extraction."""
    
    reference_path = PROJECT_ROOT / reference_file
    output_path = PROJECT_ROOT / output_file
    
    with open(reference_path, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    # Use subset for cost control (though Groq is cheap)
    subset = reference[:max_cves]
    
    print(f"Evaluating Llama 3 on {len(subset)} CVEs...")
    print("Using Groq free tier (1M tokens/day)")
    print("=" * 70)
    
    results = []
    total_tokens = 0
    run_variations = {}  # Track variance across runs
    
    for i, ref in enumerate(subset):
        cve_id = ref['cve_id']
        description = ref['description']
        
        print(f"[{i+1}/{len(subset)}] {cve_id}...", end=" ")
        
        # Multiple runs for variance measurement
        runs = []
        for run in range(3):  # 3 runs to measure determinism
            try:
                predicted = extract_with_llama3(cve_id, description, api_key)
                runs.append(set(predicted))
                if run == 0:
                    print(f"Extracted {len(predicted)} entities")
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                print(f"Run {run} failed: {e}")
                runs.append(set())
        
        # Use first run as primary, check variance
        primary_predicted = runs[0] if runs else set()
        
        # Calculate variance across runs
        if len(runs) >= 2:
            all_entities = set().union(*runs)
            variance = sum(1 for e in all_entities if not all(e in r for r in runs))
            run_variations[cve_id] = variance
        
        actual_classes = set(ref.get('ground_truth_classes', []))
        metrics = calculate_metrics(primary_predicted, actual_classes)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(primary_predicted),
            'actual': list(actual_classes),
            'metrics': metrics,
            'run_variance': run_variations.get(cve_id, 0),
            'all_runs': [list(r) for r in runs]
        })
        
        # Estimate tokens (rough)
        total_tokens += len(description.split()) * 2 + 100  # prompt + response
    
    # Aggregate
    all_pred = set()
    all_actual = set()
    for r in results:
        all_pred.update(r['predicted'])
        all_actual.update(r['actual'])
    
    overall = calculate_metrics(all_pred, all_actual)
    
    # Calculate average variance
    avg_variance = sum(run_variations.values()) / len(run_variations) if run_variations else 0
    
    summary = {
        'system': 'Llama 3 70B (Groq)',
        'total_cves': len(subset),
        'overall_metrics': overall,
        'avg_run_variance': round(avg_variance, 3),
        'total_estimated_tokens': total_tokens,
        'per_cve_results': results
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("LLAMA 3 EVALUATION RESULTS")
    print("=" * 70)
    print(f"CVEs evaluated: {len(subset)}")
    print(f"Precision: {overall['precision']:.3f}")
    print(f"Recall:    {overall['recall']:.3f}")
    print(f"F1-Score:  {overall['f1']:.3f}")
    print(f"Run variance (avg entities differing across 3 runs): {avg_variance:.2f}")
    print(f"Estimated tokens used: {total_tokens:,}")
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


def compare_all_systems():
    """Generate comparison table of all evaluated systems."""
    
    systems = {}
    
    files = {
        'CyberRule': 'evaluation/cyberrule_evaluation.json',
        'Baseline': 'evaluation/baseline_evaluation.json',
        'Llama 3': 'evaluation/llama3_evaluation.json'
    }
    
    for name, filepath in files.items():
        path = PROJECT_ROOT / filepath
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                systems[name] = data.get('overall_metrics', {})
    
    if not systems:
        print("No evaluation results found.")
        return
    
    print("\n" + "=" * 70)
    print("SYSTEM COMPARISON TABLE")
    print("=" * 70)
    print(f"{'System':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Variance':>10}")
    print("-" * 70)
    
    for name, metrics in systems.items():
        var = metrics.get('variance', 0) if 'variance' in metrics else 'N/A'
        var_str = f"{var:.3f}" if isinstance(var, float) else var
        print(f"{name:<15} {metrics.get('precision', 0):>10.3f} "
              f"{metrics.get('recall', 0):>10.3f} "
              f"{metrics.get('f1', 0):>10.3f} "
              f"{var_str:>10}")
    
    print("=" * 70)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference', default='evaluation/reference_standard_200.json')
    parser.add_argument('--output', default='evaluation/llama3_evaluation.json')
    parser.add_argument('--max', type=int, default=100, help='Max CVEs to evaluate')
    parser.add_argument('--compare', action='store_true', help='Show comparison table')
    args = parser.parse_args()
    
    if args.compare:
        compare_all_systems()
        exit(0)
    
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key:
        print("Error: Set GROQ_API_KEY environment variable")
        print("Get free API key at: https://console.groq.com/keys")
        print("Then: export GROQ_API_KEY='gsk_...'")
        exit(1)
    
    evaluate_llama3(args.reference, args.output, api_key, args.max)
