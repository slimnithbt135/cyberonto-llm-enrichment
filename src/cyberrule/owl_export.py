#!/usr/bin/env python3
"""
OWL/RDF Export for CyberRule
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import os
import re
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, OWL
from typing import List, Dict


class OWLExporter:
    """Export CyberRule extractions to OWL/RDF formats."""
    
    def __init__(self, namespace: str = "http://cyberrule.org/ontology#"):
        self.ns = Namespace(namespace)
        self.g = Graph()
        self.g.bind("cr", self.ns)
        self.g.bind("owl", OWL)
        self.g.bind("rdfs", RDFS)
        self._add_ontology_header()
    
    def _add_ontology_header(self):
        """Add OWL ontology metadata."""
        ontology = self.ns.CyberRuleOntology
        self.g.add((ontology, RDF.type, OWL.Ontology))
        self.g.add((ontology, RDFS.label, Literal("CyberRule CVE Ontology")))
        self.g.add((ontology, RDFS.comment, Literal("Deterministic rule-based extraction from NVD")))
        self.g.add((ontology, OWL.versionInfo, Literal("1.0.0")))
        self.g.add((ontology, RDFS.seeAlso, 
                   URIRef("https://github.com/slimnithbt135/cyberonto-llm-enrichment")))
    
    def _sanitize_uri(self, name: str) -> str:
        """Convert to valid URI component - remove ALL spaces and special chars."""
        # Remove all whitespace
        name = re.sub(r'\s+', '', name)
        # Remove pipe and other special characters
        name = re.sub(r'[|&<>\'\"]', '', name)
        # Keep only alphanumeric, underscore, hyphen
        name = re.sub(r'[^\w\-]', '', name)
        return name
    
    def add_extraction(self, cve_id: str, extraction: Dict):
        """Add single CVE extraction to graph."""
        # Sanitize CVE ID
        cve_uri = URIRef(self.ns[self._sanitize_uri(cve_id)])
        self.g.add((cve_uri, RDF.type, self.ns.CVE))
        
        # Add classes as types (sanitized)
        for cls in extraction.get("classes", []):
            safe_cls = self._sanitize_uri(cls)
            if safe_cls:  # Only add if not empty
                class_uri = URIRef(self.ns[safe_cls])
                self.g.add((cve_uri, self.ns.hasClass, class_uri))
                self.g.add((class_uri, RDF.type, self.ns.SecurityClass))
        
        # Add relations (sanitized)
        for rel in extraction.get("relations", []):
            subj = URIRef(self.ns[self._sanitize_uri(rel["subject"])])
            pred = URIRef(self.ns[self._sanitize_uri(rel["predicate"])])
            obj = URIRef(self.ns[self._sanitize_uri(rel["object"])])
            self.g.add((subj, pred, obj))
        
        # Add axioms as subclass relations
        for axiom in extraction.get("axioms", []):
            if "⊑" in axiom:
                parts = axiom.split("⊑")
                if len(parts) == 2:
                    sub = URIRef(self.ns[self._sanitize_uri(parts[0].strip())])
                    sup = URIRef(self.ns[self._sanitize_uri(parts[1].strip())])
                    self.g.add((sub, RDFS.subClassOf, sup))
    
    def add_batch(self, extractions: List[Dict]):
        """Add multiple CVE extractions."""
        for item in extractions:
            cve_id = item.get("id", "UNKNOWN")
            extraction = item.get("llm_output", {})
            self.add_extraction(cve_id, extraction)
    
    def to_turtle(self, output_path: str):
        """Serialize to Turtle format."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        self.g.serialize(destination=output_path, format="turtle")
        return output_path
    
    def to_rdfxml(self, output_path: str):
        """Serialize to RDF/XML (OWL) format."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        self.g.serialize(destination=output_path, format="xml")
        return output_path
    
    def get_stats(self) -> Dict:
        """Get graph statistics."""
        return {
            "triples": len(self.g),
            "subjects": len(set(self.g.subjects())),
            "predicates": len(set(self.g.predicates())),
            "objects": len(set(self.g.objects()))
        }
