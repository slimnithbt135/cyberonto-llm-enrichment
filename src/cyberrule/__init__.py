"""
CyberRule: Deterministic Rule-Based Ontology Enrichment
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

__version__ = "1.0.0"
__author__ = "Thabet Slimani"
__email__ = "thabet.slimani@gmail.com"

from .extractor import CyberRuleExtractor, Pattern, Triple
from .patterns_data import VULN_PATTERNS, PRODUCT_PATTERNS, COMPONENT_TYPES, PRIVILEGE_PATTERNS
from .owl_export import OWLExporter

__all__ = [
    "CyberRuleExtractor",
    "Pattern",
    "Triple",
    "OWLExporter",
    "VULN_PATTERNS",
    "PRODUCT_PATTERNS",
    "COMPONENT_TYPES",
    "PRIVILEGE_PATTERNS",
]
