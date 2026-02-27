#!/usr/bin/env python3
"""
Command-Line CVE Annotation Tool
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime


class CLIAnnotator:
    def __init__(self, annotator_id='annotator_001'):
        self.annotator_id = annotator_id
        self.input_dir = Path('annotations/to_annotate')
        self.output_dir = Path('annotations/annotated')
        self.output_dir.mkdir(exist_ok=True)
        
        # Load progress
        self.completed = set(f.stem for f in self.output_dir.glob('CVE-*.json'))
        self.pending = [f for f in self.input_dir.glob('CVE-*.json') 
                       if f.stem not in self.completed]
        
        print(f"Annotator: {annotator_id}")
        print(f"Completed: {len(self.completed)}")
        print(f"Pending: {len(self.pending)}")
    
    def annotate(self):
        """Main annotation loop."""
        for cve_file in sorted(self.pending):
            self.annotate_single(cve_file)
            
            cont = input("\nContinue to next? (y/n): ").lower()
            if cont != 'y':
                break
        
        print(f"\nAnnotated {len(self.completed)} CVEs total")
    
    def annotate_single(self, cve_file: Path):
        """Annotate single CVE."""
        with open(cve_file, 'r') as f:
            cve = json.load(f)
        
        print("\n" + "=" * 70)
        print(f"CVE: {cve['cve_id']}")
        print("=" * 70)
        print(f"\nDescription:\n{cve['description']}\n")
        
        entities = []
        
        while True:
            print(f"\nCurrent entities: {len(entities)}")
            for i, e in enumerate(entities, 1):
                print(f"  {i}. [{e['type']}] {e['text']} → {e['normalized']}")
            
            print("\nOptions:")
            print("  1. Add entity")
            print("  2. Save and continue")
            print("  3. Skip this CVE")
            
            choice = input("Select: ").strip()
            
            if choice == '1':
                entity = self._prompt_entity(cve['description'])
                if entity:
                    entities.append(entity)
            elif choice == '2':
                self._save_annotation(cve, entities)
                return
            elif choice == '3':
                print("Skipped")
                return
    
    def _prompt_entity(self, description: str) -> dict:
        """Prompt for entity details."""
        print(f"\nSelect text from: {description[:100]}...")
        
        text = input("Exact text span: ").strip()
        if not text:
            return None
        
        print("\nEntity types:")
        types = ['VulnerabilityType', 'AffectedProduct', 'Vendor', 'Version',
                'AttackVector', 'Impact', 'PrivilegeRequired', 'Scope']
        for i, t in enumerate(types, 1):
            print(f"  {i}. {t}")
        
        type_idx = int(input("Select type (number): ")) - 1
        entity_type = types[type_idx] if 0 <= type_idx < len(types) else 'Unknown'
        
        normalized = input(f"Normalized form [{text}]: ").strip() or text
        
        confidence = input("Confidence (1-5) [5]: ").strip() or '5'
        
        return {
            'id': f"T{len([e for e in []])+1}",  # Will be renumbered
            'type': entity_type,
            'text': text,
            'normalized': normalized,
            'confidence': int(confidence)
        }
    
    def _save_annotation(self, cve: dict, entities: list):
        """Save annotation to file."""
        # Renumber entities
        for i, e in enumerate(entities, 1):
            e['id'] = f"T{i}"
        
        annotation = {
            'cve_id': cve['cve_id'],
            'description': cve['description'],
            'metadata': {
                'annotator': self.annotator_id,
                'annotation_date': datetime.now().isoformat(),
                'total_entities': len(entities)
            },
            'entities': entities,
            'relations': [],
            'axioms': []
        }
        
        output_file = self.output_dir / f"{cve['cve_id']}.json"
        with open(output_file, 'w') as f:
            json.dump(annotation, f, indent=2)
        
        self.completed.add(cve['cve_id'])
        print(f"✓ Saved to {output_file}")


def export_gold_standard():
    """Export all annotations as gold standard."""
    output_dir = Path('annotations/annotated')
    annotations = []
    
    for f in sorted(output_dir.glob('CVE-*.json')):
        with open(f, 'r') as fp:
            annotations.append(json.load(fp))
    
    gold_standard = {
        'metadata': {
            'dataset_name': 'CyberRule Gold Standard 2023',
            'version': '1.0.0',
            'creation_date': datetime.now().isoformat(),
            'total_cves': len(annotations),
            'total_entities': sum(len(a['entities']) for a in annotations),
            'annotators': list(set(a['metadata']['annotator'] for a in annotations))
        },
        'annotations': annotations
    }
    
    with open('annotations/gold_standard_314.json', 'w') as f:
        json.dump(gold_standard, f, indent=2)
    
    print(f"✓ Exported {len(annotations)} annotations to gold_standard_314.json")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--annotator', default='annotator_001', help='Annotator ID')
    parser.add_argument('--export', action='store_true', help='Export gold standard')
    args = parser.parse_args()
    
    if args.export:
        export_gold_standard()
    else:
        annotator = CLIAnnotator(args.annotator)
        annotator.annotate()
