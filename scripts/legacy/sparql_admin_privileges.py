""" 
sparql_admin_privileges.py
==========================
Author: Thabet Slimani
This script queries the CyberOnto RDF triples to find all vulnerabilities
that require 'Administrator' privileges.

Usage:
    python scripts/sparql_admin_privileges.py
Requires:
    pip install rdflib
"""

from rdflib import Graph

TTL_FILE = "outputs/cyberonto_enriched.ttl"

def query_admin_required_vulns(file_path):
    g = Graph()
    g.parse(file_path, format="turtle")

    query = '''
    PREFIX : <http://example.org/ontology#>
    SELECT ?vuln
    WHERE {
      ?vuln :requires :Administrator .
    }
    '''

    print("🔐 CVEs requiring Administrator privileges:")
    for row in g.query(query):
        print(f"➡️ {row.vuln}")

if __name__ == "__main__":
    query_admin_required_vulns(TTL_FILE)
