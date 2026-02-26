#!/usr/bin/env python3
"""
Convert CyberRule extraction results to OWL/TTL formats
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""
import sys
import json
from pathlib import Path
# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))
from cyberrule import OWLExporter
def main():
    import argparse
    parser = argparse.ArgumentParser(description='Convert CyberRule output to OWL')
    parser.add_argument('--input', '-i', default='output/results.json', help='Input JSON')
    parser.add_argument('--output', '-o', default='output/cyberrule.ttl', help='Output TTL')
    parser.add_argument('--format', '-f', choices=['ttl', 'owl'], default='ttl', help='Format')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("CyberRule OWL Converter")
    print("Author: Thabet Slimani <thabet.slimani@gmail.com>")
    print("=" * 60)
    
    # Load results
    print(f"\nLoading: {args.input}")
    with open(args.input, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Loaded {len(data)} CVE extractions")
        # Convert
    print("\nConverting to OWL...")
    exporter = OWLExporter()
    exporter.add_batch(data)
        # Export
    if args.format == 'ttl':
        output = exporter.to_turtle(args.output)
    else:
        output = exporter.to_rdfxml(args.output.replace('.ttl', '.owl'))
    
    stats = exporter.get_stats()
        print(f"\n✓ Saved to: {output}")
    print(f"  Triples: {stats['triples']:,}")
    print(f"  Unique subjects: {stats['subjects']:,}")
    print(f"  Unique predicates: {stats['predicates']:,}")
    print(f"  Unique objects: {stats['objects']:,}")
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
