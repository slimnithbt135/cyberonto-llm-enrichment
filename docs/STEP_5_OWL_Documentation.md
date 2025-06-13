# 🧠 Step 5: OWL Ontology Generation and Protégé Integration

This step converts enriched RDF triples (in Turtle format) into an OWL-compatible RDF/XML file. The resulting `.owl` file can be loaded into semantic web tools such as **Protégé** for reasoning, validation, and ontology editing.

---

## 📥 Input
- `outputs/cyberonto_enriched.ttl`: The enriched CVE data in Turtle format, generated in Step 4.

## 📤 Output
- `outputs/cyberonto.owl`: An RDF/XML version of the same data, ready to import in OWL-compatible tools.

---

## 🧪 Script

The conversion is done using:
```bash
scripts/convert_ttl_to_owl.py
```

### Usage:
```bash
cd scripts
python convert_ttl_to_owl.py
```

If successful, you'll see:
```
✅ OWL ontology saved to: outputs/cyberonto.owl
```

---

## 📊 Importing into Protégé

To visualize the enriched ontology:

1. Open **Protégé**
2. Go to `File → Open...`
3. Select the file `outputs/cyberonto.owl`
4. Explore:
   - `Vulnerability` individuals (CVE instances)
   - Extracted `classes`, `relations`, and `axioms`
   - Use reasoners for semantic validation

---

## 📦 Git Tracking

The following files are added in this step:

- `scripts/convert_ttl_to_owl.py`: Conversion script
- `outputs/cyberonto.owl`: RDF/XML file (if generated)

Commit command:
```bash
git add scripts/convert_ttl_to_owl.py outputs/cyberonto.owl
git commit -m "Add OWL conversion script and RDF/XML output for Protégé integration"
git push origin main
```

---

This completes the semantic interoperability step, making the enriched cybersecurity ontology compatible with formal OWL tools and reasoning environments.
