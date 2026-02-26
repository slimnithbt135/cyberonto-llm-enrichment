#!/usr/bin/env python3
"""
5-Fold Cross-Validation Against Ground Truth
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import sys
import numpy as np
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from cyberrule import CyberRuleExtractor


def normalize_entity(entity: Dict) -> Tuple[str, str]:
    """Normalize entity for comparison."""
    entity_type = entity.get('type', 'Unknown')
    text = entity.get('normalized', entity.get('text', '')).lower().strip()
    # Remove punctuation
    text = ''.join(c for c in text if c.isalnum())
    return (entity_type, text)


def entities_match(pred: Tuple, gold: Tuple) -> bool:
    """Check if predicted entity matches ground truth."""
    return pred[0] == gold[0] and pred[1] == gold[1]


def calculate_metrics(predicted: List[Tuple], actual: List[Tuple]) -> Dict:
    """Calculate precision, recall, F1."""
    # Find matches
    tp = 0
    matched_gold = set()
    
    for p in predicted:
        for i, g in enumerate(actual):
            if i in matched_gold:
                continue
            if entities_match(p, g):
                tp += 1
                matched_gold.add(i)
                break
    
    fp = len(predicted) - tp
    fn = len(actual) - tp
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': tp,
        'fp': fp,
        'fn': fn
    }


def run_cross_validation(gold_standard_path: str, n_folds: int = 5, seed: int = 42):
    """Run stratified k-fold cross-validation."""
    
    # Load gold standard
    with open(gold_standard_path, 'r') as f:
        gold = json.load(f)
    
    annotations = gold['annotations']
    print(f"Loaded {len(annotations)} gold standard annotations")
    
    # Create stratification labels (by entity count)
    labels = []
    for ann in annotations:
        n_entities = len(ann['entities'])
        if n_entities <= 5:
            labels.append('low')
        elif n_entities <= 10:
            labels.append('medium')
        else:
            labels.append('high')
    
    # Run cross-validation
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    
    fold_results = []
    
    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(annotations, labels)):
        print(f"\nFold {fold_idx + 1}/{n_folds}")
        
        test_annotations = [annotations[i] for i in test_idx]
        
        # Initialize extractor (no training needed for rule-based)
        extractor = CyberRuleExtractor.from_hardcoded()
        
        # Evaluate on test set
        all_predicted = []
        all_actual = []
        
        for ann in test_annotations:
            # Extract using CyberRule
            result = extractor.extract(ann['cve_id'], ann['description'])
            
            # Convert to comparable format
            predicted = [normalize_entity({
                'type': cls,  # Simplified - assuming class = entity type
                'text': cls,
                'normalized': cls
            }) for cls in result['classes']]
            
            actual = [normalize_entity(e) for e in ann['entities']]
            
            all_predicted.extend(predicted)
            all_actual.extend(actual)
        
        # Calculate metrics
        metrics = calculate_metrics(all_predicted, all_actual)
        fold_results.append(metrics)
        
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall: {metrics['recall']:.3f}")
        print(f"  F1: {metrics['f1']:.3f}")
        print(f"  TP: {metrics['tp']}, FP: {metrics['fp']}, FN: {metrics['fn']}")
    
    # Aggregate results
    print("\n" + "=" * 70)
    print("CROSS-VALIDATION RESULTS")
    print("=" * 70)
    
    precisions = [r['precision'] for r in fold_results]
    recalls = [r['recall'] for r in fold_results]
    f1s = [r['f1'] for r in fold_results]
    
    print(f"Precision: {np.mean(precisions):.3f} ± {np.std(precisions):.3f}")
    print(f"Recall:    {np.mean(recalls):.3f} ± {np.std(recalls):.3f}")
    print(f"F1-Score:  {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")
    
    # Confidence intervals
    from scipy import stats
    ci_f1 = stats.t.interval(0.95, len(f1s)-1, loc=np.mean(f1s), scale=stats.sem(f1s))
    print(f"F1 95% CI: [{ci_f1[0]:.3f}, {ci_f1[1]:.3f}]")
    
    print("=" * 70)
    
    return {
        'folds': fold_results,
        'precision_mean': float(np.mean(precisions)),
        'precision_std': float(np.std(precisions)),
        'recall_mean': float(np.mean(recalls)),
        'recall_std': float(np.std(recalls)),
        'f1_mean': float(np.mean(f1s)),
        'f1_std': float(np.std(f1s)),
        'f1_ci_lower': float(ci_f1[0]),
        'f1_ci_upper': float(ci_f1[1])
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--gold', '-g', default='annotations/gold_standard_314.json',
                       help='Path to gold standard')
    parser.add_argument('--folds', '-k', type=int, default=5, help='Number of folds')
    parser.add_argument('--seed', '-s', type=int, default=42, help='Random seed')
    parser.add_argument('--output', '-o', help='Save results to JSON')
    args = parser.parse_args()
    
    results = run_cross_validation(args.gold, args.folds, args.seed)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results saved to {args.output}")
