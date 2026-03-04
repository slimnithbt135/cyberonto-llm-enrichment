#!/usr/bin/env python3
"""
Standalone Llama 3 evaluation with variance measurement and bootstrap confidence intervals.
Updated for current Groq models (January 2025).
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import os
import re
import time
import numpy as np
from pathlib import Path
from typing import List, Set, Dict, Tuple
from collections import defaultdict


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


def calculate_metrics_from_counts(tp: int, fp: int, fn: int) -> dict:
    """Calculate metrics from true/false positive/negative counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': tp, 'fp': fp, 'fn': fn
    }


def bootstrap_ci(results: List[Dict], n_iterations: int = 1000, ci: float = 0.95) -> Dict:
    """
    Calculate bootstrap confidence intervals for precision, recall, and F1.
    
    Args:
        results: List of per-CVE result dictionaries with 'predicted' and 'actual' sets
        n_iterations: Number of bootstrap samples (default: 1000)
        ci: Confidence interval level (default: 0.95 for 95% CI)
    
    Returns:
        Dictionary with metric statistics and confidence intervals
    """
    print(f"  Performing bootstrap resampling ({n_iterations} iterations)...")
    
    # Store bootstrap samples
    boot_precisions = []
    boot_recalls = []
    boot_f1s = []
    
    n_samples = len(results)
    alpha = (1 - ci) / 2
    
    for i in range(n_iterations):
        # Resample with replacement
        sample_indices = np.random.choice(n_samples, size=n_samples, replace=True)
        sample = [results[idx] for idx in sample_indices]
        
        # Aggregate counts across resampled CVEs
        total_tp = sum(r['metrics']['tp'] for r in sample)
        total_fp = sum(r['metrics']['fp'] for r in sample)
        total_fn = sum(r['metrics']['fn'] for r in sample)
        
        # Calculate metrics for this bootstrap sample
        metrics = calculate_metrics_from_counts(total_tp, total_fp, total_fn)
        
        boot_precisions.append(metrics['precision'])
        boot_recalls.append(metrics['recall'])
        boot_f1s.append(metrics['f1'])
    
    # Calculate statistics
    def get_stats(values):
        return {
            'mean': np.mean(values),
            'std': np.std(values, ddof=1),
            'median': np.median(values),
            'ci_lower': np.percentile(values, alpha * 100),
            'ci_upper': np.percentile(values, (1 - alpha) * 100),
            'ci_percent': ci * 100
        }
    
    return {
        'precision': get_stats(boot_precisions),
        'recall': get_stats(boot_recalls),
        'f1': get_stats(boot_f1s),
        'n_iterations': n_iterations
    }


def mcnemar_test(cyberrule_results: List[Dict], llama_results: List[Dict]) -> Dict:
    """
    Perform McNemar's test comparing CyberRule and Llama 3.3 on paired decisions.
    
    Args:
        cyberrule_results: List of CyberRule per-CVE results
        llama_results: List of Llama 3.3 per-CVE results (same order)
    
    Returns:
        Dictionary with test statistic, p-value, and contingency table
    """
    from scipy import stats
    
    # Build contingency table for entity-level decisions
    # We need to track: CR correct/Llama incorrect (b) vs CR incorrect/Llama correct (c)
    
    b = 0  # CyberRule correct, Llama incorrect
    c = 0  # CyberRule incorrect, Llama correct
    
    # For each CVE, compare entity-level decisions
    for cr_res, ll_res in zip(cyberrule_results, llama_results):
        cr_pred = set(cr_res['predicted'])
        cr_actual = set(cr_res['actual'])
        ll_pred = set(ll_res['predicted'])
        ll_actual = set(ll_res['actual'])
        
        # Normalize for comparison
        cr_pred_norm = {normalize_for_comparison(p) for p in cr_pred}
        cr_actual_norm = {normalize_for_comparison(a) for a in cr_actual}
        ll_pred_norm = {normalize_for_comparison(p) for p in ll_pred}
        ll_actual_norm = {normalize_for_comparison(a) for a in ll_actual}
        
        # All unique normalized entities in ground truth for this CVE
        all_entities = cr_actual_norm | ll_actual_norm
        
        for entity in all_entities:
            cr_correct = entity in cr_pred_norm and entity in cr_actual_norm
            ll_correct = entity in ll_pred_norm and entity in ll_actual_norm
            
            # Discordant pairs
            if cr_correct and not ll_correct:
                b += 1
            elif not cr_correct and ll_correct:
                c += 1
    
    # Calculate McNemar's statistic with continuity correction
    if b + c > 0:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c) if (b + c) > 0 else 0
        p_value = 1 - stats.chi2.cdf(chi2, df=1)
    else:
        chi2 = 0
        p_value = 1.0
    
    return {
        'b': b,  # CyberRule correct, Llama incorrect
        'c': c,  # CyberRule incorrect, Llama correct
        'discordant_total': b + c,
        'chi2_statistic': round(chi2, 3),
        'p_value': p_value,
        'significant': p_value < 0.05
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


def evaluate_llama3_with_variance(reference_file: str, output_file: str, api_key: str, 
                                  max_cves: int = 100, bootstrap: bool = True) -> Dict:
    """
    Evaluate Llama 3 extraction with 3-run variance measurement and optional bootstrap CIs.
    
    Args:
        reference_file: Path to reference standard JSON
        output_file: Path to save evaluation results
        api_key: Groq API key
        max_cves: Maximum number of CVEs to evaluate
        bootstrap: Whether to calculate bootstrap confidence intervals
    """
    
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    reference_path = project_root / reference_file
    output_path = project_root / output_file
    
    with open(reference_path, 'r', encoding='utf-8') as f:
        reference = json.load(f)
    
    subset = reference[:max_cves]
    
    print(f"Evaluating Llama 3.3 on {len(subset)} CVEs with variance measurement...")
    print("Using Groq API - free tier: 1M tokens/day")
    print("Running 3 executions per CVE to measure output variance")
    if bootstrap:
        print("Bootstrap CIs will be calculated after extraction")
    print("=" * 70)
    
    results = []
    total_variance_entities = 0
    
    for i, ref in enumerate(subset):
        cve_id = ref['cve_id']
        description = ref['description']
        
        print(f"[{i+1}/{len(subset)}] {cve_id}...", end=" ", flush=True)
        
        # Run 3 times to measure variance
        runs = []
        for run in range(3):
            try:
                predicted = set(extract_with_llama3(cve_id, description, api_key))
                runs.append(predicted)
                time.sleep(0.2)
            except Exception as e:
                print(f"Run {run} failed: {e}")
                runs.append(set())
        
        # Calculate variance
        if len(runs) >= 2:
            all_entities = set().union(*runs)
            variance_count = sum(1 for e in all_entities if not all(e in r for r in runs))
            total_variance_entities += variance_count
        else:
            variance_count = 0
        
        # Use first run as primary for metrics
        primary_predicted = runs[0] if runs else set()
        actual = set(ref.get('ground_truth_classes', []))
        
        metrics = calculate_metrics(primary_predicted, actual)
        
        results.append({
            'cve_id': cve_id,
            'predicted': list(primary_predicted),
            'actual': list(actual),
            'metrics': metrics,
            'run_variance': variance_count,
            'all_runs': [list(r) for r in runs]
        })
        
        print(f"Found {len(primary_predicted)} entities, variance={variance_count}, F1={metrics['f1']:.3f}")
    
    # Aggregate metrics
    all_pred = set()
    all_actual = set()
    for r in results:
        all_pred.update(r['predicted'])
        all_actual.update(r['actual'])
    
    overall = calculate_metrics(all_pred, all_actual)
    
    # Calculate average variance
    avg_variance = total_variance_entities / len(subset) if subset else 0
    
    # Bootstrap confidence intervals
    bootstrap_stats = None
    if bootstrap and len(results) > 0:
        print("\nCalculating bootstrap confidence intervals...")
        bootstrap_stats = bootstrap_ci(results, n_iterations=1000, ci=0.95)
    
    summary = {
        'system': 'Llama 3.3 70B (Groq)',
        'model': 'llama-3.3-70b-versatile',
        'total_cves': len(subset),
        'overall_metrics': overall,
        'avg_run_variance': round(avg_variance, 2),
        'total_variance_entities': total_variance_entities,
        'bootstrap_ci': bootstrap_stats,
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
    print(f"Average variance (entities differing across 3 runs): {avg_variance:.2f}")
    print(f"Total variance entities across all CVEs: {total_variance_entities}")
    
    if bootstrap_stats:
        print("\nBootstrap 95% Confidence Intervals (1000 iterations):")
        p_stats = bootstrap_stats['precision']
        print(f"  Precision: {p_stats['mean']:.3f} ± {p_stats['std']:.3f} "
              f"[{p_stats['ci_lower']:.3f} – {p_stats['ci_upper']:.3f}]")
        r_stats = bootstrap_stats['recall']
        print(f"  Recall:    {r_stats['mean']:.3f} ± {r_stats['std']:.3f} "
              f"[{r_stats['ci_lower']:.3f} – {r_stats['ci_upper']:.3f}]")
    
    print(f"\nResults saved to: {output_path}")
    print("=" * 70)
    
    return summary


def compare_systems(cyberrule_file: str, llama_file: str, output_file: str = None):
    """
    Compare CyberRule and Llama 3.3 results with McNemar's test and statistical analysis.
    
    Args:
        cyberrule_file: Path to CyberRule evaluation JSON
        llama_file: Path to Llama 3.3 evaluation JSON
        output_file: Optional path to save comparison results
    """
    
    print("=" * 70)
    print("STATISTICAL COMPARISON: CyberRule vs Llama 3.3")
    print("=" * 70)
    
    # Load results
    with open(cyberrule_file, 'r', encoding='utf-8') as f:
        cr_data = json.load(f)
    with open(llama_file, 'r', encoding='utf-8') as f:
        ll_data = json.load(f)
    
    cr_results = cr_data.get('per_cve_results', cr_data.get('results', []))
    ll_results = ll_data.get('per_cve_results', ll_data.get('results', []))
    
    # Ensure same CVEs are compared
    cr_cves = {r['cve_id'] for r in cr_results}
    ll_cves = {r['cve_id'] for r in ll_results}
    common_cves = cr_cves & ll_cves
    
    print(f"CyberRule CVEs: {len(cr_cves)}")
    print(f"Llama 3.3 CVEs: {len(ll_cves)}")
    print(f"Common CVEs for comparison: {len(common_cves)}")
    
    # Filter to common CVEs
    cr_results = [r for r in cr_results if r['cve_id'] in common_cves]
    ll_results = [r for r in ll_results if r['cve_id'] in common_cves]
    
    # Sort by CVE ID to ensure pairing
    cr_results.sort(key=lambda x: x['cve_id'])
    ll_results.sort(key=lambda x: x['cve_id'])
    
    # Bootstrap CIs for both systems
    print("\nCalculating bootstrap CIs for CyberRule...")
    cr_bootstrap = bootstrap_ci(cr_results, n_iterations=1000, ci=0.95)
    
    print("Calculating bootstrap CIs for Llama 3.3...")
    ll_bootstrap = bootstrap_ci(ll_results, n_iterations=1000, ci=0.95)
    
    # McNemar's test
    print("\nPerforming McNemar's test...")
    mcnemar = mcnemar_test(cr_results, ll_results)
    
    # Print comparison results
    print("\n" + "=" * 70)
    print("COMPARISON RESULTS")
    print("=" * 70)
    
    print("\nCyberRule Performance:")
    cr_overall = cr_data.get('overall_metrics', {})
    print(f"  Precision: {cr_overall.get('precision', 0):.3f}")
    if cr_bootstrap:
        p = cr_bootstrap['precision']
        print(f"    95% CI: [{p['ci_lower']:.3f} – {p['ci_upper']:.3f}] "
              f"(±{(p['ci_upper']-p['ci_lower'])/2:.3f})")
    
    print("\nLlama 3.3 Performance:")
    ll_overall = ll_data.get('overall_metrics', {})
    print(f"  Precision: {ll_overall.get('precision', 0):.3f}")
    if ll_bootstrap:
        p = ll_bootstrap['precision']
        print(f"    95% CI: [{p['ci_lower']:.3f} – {p['ci_upper']:.3f}] "
              f"(±{(p['ci_upper']-p['ci_lower'])/2:.3f})")
    
    print(f"\nMcNemar's Test Results:")
    print(f"  Discordant pairs (CR correct, Llama incorrect): {mcnemar['b']}")
    print(f"  Discordant pairs (CR incorrect, Llama correct): {mcnemar['c']}")
    print(f"  Total discordant pairs: {mcnemar['discordant_total']}")
    print(f"  χ² statistic: {mcnemar['chi2_statistic']}")
    print(f"  p-value: {mcnemar['p_value']:.6f}")
    print(f"  Statistically significant (p < 0.05): {mcnemar['significant']}")
    
    # Check CI overlap
    if cr_bootstrap and ll_bootstrap:
        cr_upper = cr_bootstrap['precision']['ci_upper']
        cr_lower = cr_bootstrap['precision']['ci_lower']
        ll_upper = ll_bootstrap['precision']['ci_upper']
        ll_lower = ll_bootstrap['precision']['ci_lower']
        
        overlap = not (cr_upper < ll_lower or ll_upper < cr_lower)
        print(f"\n95% CI Overlap for Precision: {overlap}")
        if not overlap:
            print("  → Non-overlapping CIs indicate robust difference")
    
    # Save comparison
    comparison = {
        'common_cves': len(common_cves),
        'cyberrule': {
            'precision': cr_overall.get('precision', 0),
            'bootstrap_ci': cr_bootstrap['precision'] if cr_bootstrap else None
        },
        'llama3': {
            'precision': ll_overall.get('precision', 0),
            'bootstrap_ci': ll_bootstrap['precision'] if ll_bootstrap else None
        },
        'mcnemar_test': mcnemar,
        'statistical_summary': {
            'cyberrule_superior': mcnemar['b'] > mcnemar['c'],
            'significant_difference': mcnemar['significant'],
            'ci_overlap_precision': overlap if (cr_bootstrap and ll_bootstrap) else None
        }
    }
    
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2)
        print(f"\nComparison results saved to: {output_file}")
    
    print("=" * 70)
    
    return comparison


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Evaluate Llama 3.3 and compare with CyberRule')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Evaluate command
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate Llama 3.3')
    eval_parser.add_argument('--reference', default='evaluation/reference_standard_200.json')
    eval_parser.add_argument('--output', default='evaluation/llama3_evaluation.json')
    eval_parser.add_argument('--max', type=int, default=100)
    eval_parser.add_argument('--no-bootstrap', action='store_true', help='Skip bootstrap CI calculation')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare CyberRule vs Llama 3.3')
    compare_parser.add_argument('--cyberrule', default='evaluation/cyberrule_evaluation.json')
    compare_parser.add_argument('--llama', default='evaluation/llama3_evaluation.json')
    compare_parser.add_argument('--output', default='evaluation/statistical_comparison.json')
    
    args = parser.parse_args()
    
    api_key = os.environ.get('GROQ_API_KEY')
    
    if args.command == 'evaluate' or args.command is None:
        if not api_key:
            print("Error: Set GROQ_API_KEY environment variable")
            print("Get free API key at: https://console.groq.com/keys")
            exit(1)
        
        evaluate_llama3_with_variance(
            args.reference, 
            args.output, 
            api_key, 
            args.max,
            bootstrap=not args.no_bootstrap
        )
    
    elif args.command == 'compare':
        compare_systems(args.cyberrule, args.llama, args.output)
