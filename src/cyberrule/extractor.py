#!/usr/bin/env python3
"""
CyberRule Extractor - Core enrichment engine.
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import re
import json
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Triple:
    """RDF triple with provenance tracking."""
    subject: str
    predicate: str
    object: str
    confidence: float = field(default=1.0)
    provenance: str = field(default="")


class Pattern:
    """Compiled regex pattern with metadata."""
    
    def __init__(self, name: str, regex: str, category: str, 
                 predicate: Optional[str] = None, priority: int = 0, 
                 source: str = "Custom"):
        self.name = name
        self.regex = re.compile(regex, re.IGNORECASE | re.UNICODE)
        self.category = category
        self.predicate = predicate or f"has{category}"
        self.priority = priority
        self.source = source
        self.hits = 0
        self.misses = 0
    
    def match(self, text: str) -> List[Tuple[int, int, str, float]]:
        """Find all matches with confidence scores."""
        matches = []
        for m in self.regex.finditer(text):
            matched_text = m.group()
            confidence = self._calculate_confidence(matched_text, text, m.start(), m.end())
            matches.append((m.start(), m.end(), matched_text, confidence))
            self.hits += 1
        
        if not matches:
            self.misses += 1
        
        return matches
    
    def _calculate_confidence(self, match: str, context: str, start: int, end: int) -> float:
        """Calculate confidence based on context."""
        confidence = 1.0
        
        if len(match) < 3:
            confidence *= 0.8
        
        prefix = context[max(0, start-30):start].lower()
        security_terms = ['vulnerability', 'exploit', 'attack', 'flaw', 'cve', 'security']
        if any(term in prefix for term in security_terms):
            confidence *= 1.1
        
        if 'reference' in prefix or 'http' in context[end:end+20]:
            confidence *= 0.7
        
        return min(confidence, 1.0)


class CyberRuleExtractor:
    """
    Main extraction engine for CyberRule.
    Deterministic, reproducible, fully offline.
    """
    
    def __init__(self, patterns: List[Pattern]):
        self.patterns = sorted(patterns, key=lambda p: p.priority, reverse=True)
        self.category_index = defaultdict(list)
        for pattern in self.patterns:
            self.category_index[pattern.category].append(pattern)
        
        logger.info(f"Initialized CyberRuleExtractor with {len(patterns)} patterns")
    
    @classmethod
    def from_hardcoded(cls) -> "CyberRuleExtractor":
        """Load patterns from hardcoded dictionaries."""
        from .patterns_data import VULN_PATTERNS, PRODUCT_PATTERNS, COMPONENT_TYPES, PRIVILEGE_PATTERNS
        
        patterns = []
        
        for regex, label in VULN_PATTERNS.items():
            patterns.append(Pattern(
                name=f"Vuln_{label}",
                regex=regex,
                category="VulnerabilityType",
                predicate="hasVulnerabilityType",
                priority=100,
                source="CWE"
            ))
        
        for regex, label in PRODUCT_PATTERNS.items():
            patterns.append(Pattern(
                name=f"Prod_{label}",
                regex=regex,
                category="Product",
                predicate="affectsProduct",
                priority=90,
                source="CPE"
            ))
        
        for regex, label in COMPONENT_TYPES.items():
            patterns.append(Pattern(
                name=f"Comp_{label}",
                regex=regex,
                category="Component",
                predicate="affectsComponent",
                priority=80,
                source="ATTACK"
            ))
        
        for regex, label in PRIVILEGE_PATTERNS.items():
            patterns.append(Pattern(
                name=f"Priv_{label}",
                regex=regex,
                category="Privilege",
                predicate="requiresPrivilege",
                priority=70,
                source="CVSS"
            ))
        
        return cls(patterns)
    
    def extract(self, cve_id: str, description: str) -> Dict:
        """Extract semantic information from CVE description."""
        classes = set()
        relations = []
        axioms = []
        
        text_lower = description.lower()
        matched_spans = set()
        
        products_found = []
        components_found = []
        privileges_found = []
        vuln_types_found = []
        
        for pattern in self.patterns:
            matches = pattern.match(description)
            
            for start, end, matched_text, confidence in matches:
                if self._is_overlapping(start, end, matched_spans):
                    continue
                
                normalized = self._normalize_value(matched_text, pattern.category)
                classes.add(normalized)
                
                if pattern.category == "VulnerabilityType":
                    vuln_types_found.append(normalized)
                elif pattern.category == "Product":
                    products_found.append((normalized, matched_text))
                    version = self._extract_version(description, end)
                    if version:
                        versioned = f"{normalized}_v{version}"
                        classes.add(versioned)
                elif pattern.category == "Component":
                    components_found.append(normalized)
                elif pattern.category == "Privilege":
                    privileges_found.append(normalized)
                
                matched_spans.add((start, end))
        
        # Build relationships
        for vuln in vuln_types_found:
            for component in components_found:
                relations.append({
                    "subject": vuln,
                    "predicate": "affects",
                    "object": component
                })
            
            for priv in privileges_found:
                relations.append({
                    "subject": vuln,
                    "predicate": "requires",
                    "object": priv
                })
            
            for product, raw_text in products_found:
                relations.append({
                    "subject": vuln,
                    "predicate": "inProduct",
                    "object": product
                })
        
        # Generate axioms
        if any("CrossSiteScripting" in c for c in classes):
            axioms.append("CrossSiteScripting ⊑ ClientSideAttack")
        if any("SQLInjection" in c for c in classes):
            axioms.append("SQLInjection ⊑ DatabaseAttack")
        if any("BufferOverflow" in c for c in classes):
            axioms.append("BufferOverflow ⊑ MemoryCorruption")
        
        if "javascript" in text_lower and any("CrossSiteScripting" in c for c in classes):
            classes.add("JavaScriptInjection")
            relations.append({
                "subject": "JavaScriptInjection",
                "predicate": "leadsTo",
                "object": "CrossSiteScripting"
            })
        
        return {
            "classes": sorted(classes),
            "relations": relations,
            "axioms": axioms
        }
    
    def _is_overlapping(self, start: int, end: int, existing: Set[Tuple[int, int]]) -> bool:
        """Check if span overlaps with existing matches."""
        for s, e in existing:
            if not (end <= s or start >= e):
                return True
        return False
    
       def _normalize_value(self, value: str, category: str) -> str:
        """Normalize extracted value to valid URI component matching ground truth conventions."""
        value = value.strip()
        
        # Remove all whitespace and special characters for base normalization
        value = re.sub(r'\s+', '', value)
        value = re.sub(r'\|', '', value)
        value = re.sub(r'[^\w\-]', '', value)
        
        if category == "VulnerabilityType":
            # Use ground truth convention (SqlInjection not SQLInjection)
            # Map acronyms to CWE naming conventions
            cwe_naming_map = {
                'SQL': 'Sql',
                'XSS': 'Xss',
                'CSRF': 'Csrf',
                'XXE': 'Xxe',
                'SSRF': 'Ssrf',
                'RCE': 'Rce',
                'DOS': 'Dos',
                'LDAP': 'Ldap',
                'XPath': 'Xpath',
                'HTML': 'Html',
                'XML': 'Xml',
                'JSON': 'Json',
                'JWT': 'Jwt',
                'OAuth': 'Oauth',
                'SAML': 'Saml'
            }
            
            # Split on camelCase boundaries
            words = re.split(r'(?=[A-Z])', value)
            words = [w for w in words if w]
            if not words:
                words = [value]
            
            normalized_words = []
            for word in words:
                if word in cwe_naming_map:
                    normalized_words.append(cwe_naming_map[word])
                else:
                    normalized_words.append(word.capitalize())
            
            value = ''.join(normalized_words)
            
        elif category in ["Product", "Component", "Privilege"]:
            value = value.title()
        
        return value
    
    def _extract_version(self, text: str, start_pos: int) -> Optional[str]:
        """Extract version number following a match."""
        suffix = text[start_pos:start_pos+30]
        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', suffix)
        if version_match:
            return version_match.group(1)
        return None
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics."""
        return {
            "total_patterns": len(self.patterns),
            "patterns_by_category": {
                cat: len(patterns) 
                for cat, patterns in self.category_index.items()
            },
            "patterns_by_source": self._count_by_source(),
        }
    
    def _count_by_source(self) -> Dict[str, int]:
        """Count patterns by source."""
        counts = defaultdict(int)
        for p in self.patterns:
            counts[p.source] += 1
        return dict(counts)
