#Author: Thabet Slimani
#Affiliation: Taif University
#Script: generate_rdf_from_cyberrule.py
#Description: Converts CyberRule-enriched CVE data in JSON format into RDF triples using the Turtle syntax.
#             This script builds class assertions, object properties, and axioms for semantic web integration.
import json
import os
from rdflib import Graph, Namespace, URIRef, Literal, RDF

# --- Configuration ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE = os.path.join(PROJECT_ROOT, "data", "cve_2023_enriched.json")
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "outputs", "cyberonto_enriched.ttl")

# --- Namespaces ---
ONTO = Namespace("http://example.org/ontology#")

def sanitize_id(cve_id):
    return cve_id.replace("-", "_")

def to_uri(term):
    return URIRef(ONTO + term)

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Input file not found at: {INPUT_FILE}")
        return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    g = Graph()
    g.bind("onto", ONTO)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)

    for record in records:
        cve_uri = to_uri("CVE_" + sanitize_id(record["id"]))
        g.add((cve_uri, RDF.type, to_uri("Vulnerability")))

        for cls in record["llm_output"]["classes"]:
            g.add((cve_uri, to_uri("hasClass"), to_uri(cls)))

        for rel in record["llm_output"]["relations"]:
            subj = to_uri(rel["subject"])
            pred = to_uri(rel["predicate"])
            obj = to_uri(rel["object"])
            g.add((subj, pred, obj))

        for axiom in record["llm_output"]["axioms"]:
            g.add((cve_uri, to_uri("hasAxiom"), Literal(axiom)))

    g.serialize(destination=OUTPUT_FILE, format="turtle")
    print(f"✅ RDF triples saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
