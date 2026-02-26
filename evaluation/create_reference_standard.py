#!/usr/bin/env python3
"""
Create reference standard from official NVD CWE mappings.
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import requests
import time
from pathlib import Path
from collections import defaultdict
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from sample_ground_truth import extract_severity, stratified_sample


def fetch_nvd_cwe(cve_id: str) -> list:
    """Fetch official CWE mappings from NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cwe_list = []
                for weakness in vulnerabilities[0].get('cve', {}).get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_list.append(desc.get('value', ''))
                return cwe_list
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
    return []


def create_reference_standard(input_file: str, output_file: str, sample_size: int = 200):
    """Create reference standard with official CWE mappings."""
    
    # FIX: Added encoding='utf-8'
    with open(input_file, 'r', encoding='utf-8') as f:
        cves = json.load(f)
    
    # Sample stratified by severity
    samples = stratified_sample(cves, sample_size // 4, seed=42)
    
    all_samples = []
    for sev, items in samples.items():
        all_samples.extend(items)
    
    print(f"Creating reference standard for {len(all_samples)} CVEs...")
    
    reference = []
    for i, cve_item in enumerate(all_samples):
        cve_id = cve_item['cve_id']
        print(f"[{i+1}/{len(all_samples)}] Processing {cve_id}...")
        
        # Fetch official CWEs
        cwes = fetch_nvd_cwe(cve_id)
        time.sleep(0.6)  # NVD API rate limit
        
        # Map CWE IDs to names
        cwe_names = [cwe_id_to_name(cwe) for cwe in cwes if cwe.startswith('CWE-')]
        
        reference.append({
            'cve_id': cve_id,
            'description': cve_item['description'],
            'severity': cve_item['severity'],
            'official_cwes': cwes,
            'official_cwe_names': cwe_names,
            'ground_truth_classes': cwe_names + extract_additional_ground_truth(cve_item['description'])
        })
    
    # FIX: Added encoding='utf-8'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(reference, f, indent=2)
    
    print(f"Reference standard saved to {output_file}")


def cwe_id_to_name(cwe_id: str) -> str:
    """Map CWE ID to normalized name."""
    cwe_map = {
        'CWE-79': 'CrossSiteScripting',
        'CWE-89': 'SqlInjection',
        'CWE-94': 'CodeInjection',
        'CWE-119': 'BufferOverflow',
        'CWE-200': 'InformationDisclosure',
        'CWE-287': 'AuthenticationBypass',
        'CWE-352': 'CrossSiteRequestForgery',
        'CWE-434': 'UnrestrictedFileUpload',
        'CWE-502': 'DeserializationOfUntrustedData',
        'CWE-918': 'ServerSideRequestForgery',
        'CWE-22': 'PathTraversal',
        'CWE-125': 'OutOfBoundsRead',
        'CWE-190': 'IntegerOverflow',
        'CWE-276': 'IncorrectPermissionAssignment',
        'CWE-362': 'RaceCondition',
        'CWE-400': 'UncontrolledResourceConsumption',
        'CWE-611': 'XmlExternalEntity',
        'CWE-798': 'UseOfHardcodedCredentials',
        'CWE-862': 'MissingAuthorization',
        'CWE-863': 'IncorrectAuthorization'
    }
    return cwe_map.get(cwe_id, cwe_id.replace('CWE-', 'Cwe'))


def extract_additional_ground_truth(description: str) -> list:
    """Extract additional ground truth indicators from description."""
    desc_lower = description.lower()
    classes = []
    
    product_patterns = {
        'microsoft': 'Microsoft',
        'adobe': 'Adobe',
        'oracle': 'Oracle',
        'cisco': 'Cisco',
        'apache': 'Apache',
        'nginx': 'Nginx',
        'wordpress': 'Wordpress',
        'joomla': 'Joomla',
        'linux': 'Linux',
        'windows': 'Windows'
    }
    
    for pattern, normalized in product_patterns.items():
        if pattern in desc_lower:
            classes.append(normalized)
    
    return list(set(classes))


if __name__ == '__main__':
    create_reference_standard(
        'data/cve_2023_preprocessed.json',
        'evaluation/reference_standard_200.json',
        sample_size=200
    )
