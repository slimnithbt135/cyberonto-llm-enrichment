#!/usr/bin/env python3
"""
Stratified Sampling for Ground Truth Annotation
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import random
import argparse
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def extract_severity(cve: dict) -> str:
    """Extract severity with better MEDIUM detection."""
    
    # 1. Try CVSS v3/v2 baseSeverity first (most reliable)
    cvss = cve.get('cvss', {})
    if isinstance(cvss, dict):
        severity = cvss.get('baseSeverity') or cvss.get('severity')
        if severity:
            return severity.upper()
    
    # 2. Check for explicit severity fields at root level
    if 'severity' in cve:
        return cve['severity'].upper()
    
    # 3. Check metrics/scoring structures
    metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics:
        severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
        if severity:
            return severity.upper()
    if 'cvssMetricV30' in metrics:
        severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
        if severity:
            return severity.upper()
    
    # 4. Pattern matching from description (fallback)
    desc = cve.get('description', '').lower()
    
    # Check explicit severity mentions first
    if 'severity: medium' in desc or 'severity:medium' in desc:
        return 'MEDIUM'
    if 'cvss' in desc and 'medium' in desc:
        return 'MEDIUM'
    
    # Critical patterns
    critical_patterns = ['remote code execution', 'rce', 'zero-day', 'zeroday', 
                        'wormable', 'critical', 'arbitrary code execution']
    if any(p in desc for p in critical_patterns):
        return 'CRITICAL'
    
    # High patterns  
    high_patterns = ['privilege escalation', 'sql injection', 'xss', 
                    'buffer overflow', 'memory corruption']
    if any(p in desc for p in high_patterns):
        return 'HIGH'
    
    # Medium patterns (expanded)
    medium_patterns = ['denial of service', 'dos', 'information disclosure', 
                      'cross-site scripting', 'csrf', 'medium', 'moderate',
                      'exposure of sensitive information', 'open redirect']
    if any(p in desc for p in medium_patterns):
        return 'MEDIUM'
    
    # Low patterns
    low_patterns = ['low severity', 'low impact', 'minor', 'negligible']
    if any(p in desc for p in low_patterns):
        return 'LOW'
    
    # Default to MEDIUM (safer than LOW for unknown)
    return 'MEDIUM'


def extract_year(cve_id: str) -> int:
    """Extract year from CVE ID (e.g., CVE-2021-12345 -> 2021)."""
    match = re.search(r'CVE-(\d{4})-', cve_id, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return datetime.now().year


def stratified_sample(cves: list, samples_per_stratum: int, seed: int = 42) -> dict:
    """
    Perform stratified sampling based on severity levels.
    Returns samples grouped by severity.
    """
    random.seed(seed)
    
    # Group by severity
    strata = defaultdict(list)
    for cve in cves:
        severity = extract_severity(cve)
        cve_id = cve.get('id', cve.get('cve_id', 'UNKNOWN'))
        strata[severity].append({
            'cve_id': cve_id,
            'severity': severity,
            'description': cve.get('description', ''),
            'year': extract_year(cve_id)
        })
    
    # Sample from each stratum
    samples = {}
    for severity, items in strata.items():
        if len(items) <= samples_per_stratum:
            samples[severity] = items
        else:
            samples[severity] = random.sample(items, samples_per_stratum)
    
    return samples


def load_cves(input_path: Path) -> list:
    """Load CVEs from JSON file (single object or list)."""
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        # Handle common wrapper formats
        if 'CVE_Items' in data:
            return data['CVE_Items']
        elif 'vulnerabilities' in data:
            return data['vulnerabilities']
        else:
            return [data]
    return []


def save_samples(samples: dict, output_path: Path, format: str = 'json', samples_per_stratum: int = 50):
    """Save sampled CVEs to output file."""
    # If output is a directory, create a filename inside it
    if output_path.is_dir():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"samples_{samples_per_stratum}_per_stratum_{timestamp}.{format}"
        output_path = output_path / filename
    
    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Flatten samples for CSV/TSV
    all_samples = []
    for severity, items in samples.items():
        all_samples.extend(items)
    
    if format == 'json':
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_samples': len(all_samples),
                    'by_severity': {k: len(v) for k, v in samples.items()}
                },
                'samples': all_samples
            }, f, indent=2)
    
    elif format in ('csv', 'tsv'):
        delimiter = ',' if format == 'csv' else '\t'
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f'cve_id{delimiter}severity{delimiter}year{delimiter}description\n')
            for item in all_samples:
                desc = item['description'].replace(delimiter, ' ').replace('\n', ' ')
                f.write(f"{item['cve_id']}{delimiter}{item['severity']}{delimiter}"
                       f"{item['year']}{delimiter}\"{desc}\"\n")


def main():
    parser = argparse.ArgumentParser(
        description='Stratified sampling of CVEs for ground truth annotation'
    )
    parser.add_argument('input', type=Path, help='Input JSON file with CVE data')
    parser.add_argument('-o', '--output', type=Path, default=Path('samples.json'),
                       help='Output file path')
    parser.add_argument('-n', '--samples', type=int, default=50,
                       help='Samples per severity stratum')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'tsv'], 
                       default='json', help='Output format')
    parser.add_argument('-s', '--seed', type=int, default=42,
                       help='Random seed for reproducibility')
    parser.add_argument('--stats', action='store_true',
                       help='Print distribution statistics')
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading CVEs from {args.input}...")
    cves = load_cves(args.input)
    print(f"Loaded {len(cves)} CVE entries")
    
    # Show distribution before sampling
    if args.stats:
        severity_counts = defaultdict(int)
        for cve in cves:
            severity_counts[extract_severity(cve)] += 1
        print("\nSeverity distribution in source data:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in severity_counts:
                print(f"  {sev}: {severity_counts[sev]}")
    
    # Perform stratified sampling
    print(f"\nSampling {args.samples} per stratum...")
    samples = stratified_sample(cves, args.samples, args.seed)
    
    # Show sample distribution
    print("\nSample distribution:")
    total = 0
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in samples:
            count = len(samples[severity])
            total += count
            print(f"  {severity}: {count}")
    print(f"  TOTAL: {total}")
    
    # Handle output path (if directory, create filename with correct sample count)
    output_path = args.output
    if output_path.is_dir():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_path / f'samples_{args.samples}_per_stratum_{timestamp}.json'
    
    # Save results
    save_samples(samples, output_path, args.format)
    print(f"\nSaved samples to {output_path}")


if __name__ == '__main__':
    main()

