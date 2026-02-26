#!/usr/bin/env python3
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cyberrule import CyberRuleExtractor

print("Loading extractor...")
extractor = CyberRuleExtractor.from_hardcoded()
print(f"Loaded {len(extractor.patterns)} patterns")

print("\nTesting extraction...")
result = extractor.extract("CVE-2023-TEST", 
    "SQL injection in Apache Tomcat 8.5 allows remote code execution")

print(f"\nClasses found: {result['classes']}")
print(f"Relations found: {len(result['relations'])}")
print(f"Axioms found: {result['axioms']}")

print("\nSUCCESS!")
