# Author: Thabet Slimani
# Affiliation: Taif University
# Script: convert_ttl_to_owl.py
# Description: Converts RDF/Turtle format to OWL (RDF/XML) for Protégé.
from rdflib import Graph
import os

# --- Configuration ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_TTL = os.path.join(PROJECT_ROOT, "outputs", "cyberonto_enriched.ttl")
OUTPUT_OWL = os.path.join(PROJECT_ROOT, "outputs", "cyberonto.owl")

def convert_ttl_to_owl():
    if not os.path.exists(INPUT_TTL):
        print(f"❌ Input TTL file not found at: {INPUT_TTL}")
        return

    g = Graph()
    g.parse(INPUT_TTL, format="turtle")

    g.serialize(destination=OUTPUT_OWL, format="xml")
    print(f"✅ OWL ontology saved to: {OUTPUT_OWL}")

if __name__ == "__main__":
    convert_ttl_to_owl()
