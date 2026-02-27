#!/usr/bin/env python3
"""
Web-based CVE Annotation Interface
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

import json
import os
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, redirect

app = Flask(__name__)

ANNOTATIONS_DIR = Path('annotations/to_annotate')
OUTPUT_DIR = Path('annotations/annotated')
ANNOTATOR_NAME = os.environ.get('ANNOTATOR', 'annotator_001')

# HTML Template
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberRule Annotation Tool</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #666; font-size: 18px; }
        .cve-id { background: #007bff; color: white; padding: 5px 15px; border-radius: 4px; font-weight: bold; }
        .description { background: #f8f9fa; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0; font-family: monospace; white-space: pre-wrap; }
        .entity-form { margin: 20px 0; padding: 20px; background: #e9ecef; border-radius: 8px; }
        .entity-list { margin: 20px 0; }
        .entity-item { background: #d4edda; padding: 10px; margin: 5px 0; border-radius: 4px; display: flex; justify-content: space-between; }
        .entity-type { font-weight: bold; color: #155724; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #0056b3; }
        .remove-btn { background: #dc3545; }
        input, select { padding: 8px; margin: 5px; border: 1px solid #ced4da; border-radius: 4px; }
        .progress { margin: 20px 0; padding: 15px; background: #fff3cd; border-radius: 4px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .confidence { display: inline-block; margin-left: 10px; }
        .confidence label { margin-right: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CyberRule Annotation Tool</h1>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/progress">Progress</a>
            <a href="/export">Export</a>
        </div>
        
        <div class="progress">
            <strong>Progress:</strong> {{ completed }} / {{ total }} annotated 
            ({{ "%.1f"|format(completed/total*100 if total > 0 else 0) }}%)
        </div>
        
        <h2>CVE: <span class="cve-id">{{ cve.cve_id }}</span></h2>
        
        <div class="description">{{ cve.description }}</div>
        
        <h3>Current Entities ({{ entities|length }})</h3>
        <div class="entity-list">
            {% for entity in entities %}
            <div class="entity-item">
                <span>
                    <span class="entity-type">[{{ entity.type }}]</span>
                    {{ entity.text }} 
                    {% if entity.normalized %}
                    → <em>{{ entity.normalized }}</em>
                    {% endif %}
                    <span class="confidence">(confidence: {{ entity.confidence }})</span>
                </span>
                <form method="POST" action="/remove_entity/{{ cve.cve_id }}/{{ loop.index0 }}" style="display:inline;">
                    <button type="submit" class="remove-btn">Remove</button>
                </form>
            </div>
            {% endfor %}
        </div>
        
        <div class="entity-form">
            <h3>Add Entity</h3>
            <form method="POST" action="/add_entity/{{ cve.cve_id }}">
                <label>Text Span:</label>
                <input type="text" name="text" placeholder="Exact text from description" required size="50">
                <br>
                <label>Type:</label>
                <select name="entity_type" required>
                    <option value="VulnerabilityType">VulnerabilityType</option>
                    <option value="AffectedProduct">AffectedProduct</option>
                    <option value="Vendor">Vendor</option>
                    <option value="Version">Version</option>
                    <option value="AttackVector">AttackVector</option>
                    <option value="Impact">Impact</option>
                    <option value="PrivilegeRequired">PrivilegeRequired</option>
                    <option value="Scope">Scope</option>
                </select>
                <br>
                <label>Normalized:</label>
                <input type="text" name="normalized" placeholder="CamelCase normalized form">
                <br>
                <label>Confidence (1-5):</label>
                <input type="number" name="confidence" min="1" max="5" value="5" class="confidence">
                <br>
                <button type="submit">Add Entity</button>
            </form>
        </div>
        
        <form method="POST" action="/save/{{ cve.cve_id }}">
            <button type="submit" style="background: #28a745; font-size: 16px; padding: 15px 30px;">
                ✅ Save & Next
            </button>
        </form>
        
        <div style="margin-top: 30px;">
            <a href="/skip/{{ cve.cve_id }}"><button style="background: #6c757d;">Skip →</button></a>
        </div>
    </div>
</body>
</html>
"""


def get_pending_cves():
    """Get list of CVEs pending annotation."""
    all_files = list(ANNOTATIONS_DIR.glob('CVE-*.json'))
    completed = list(OUTPUT_DIR.glob('CVE-*.json'))
    completed_ids = {f.stem for f in completed}
    
    pending = []
    for f in all_files:
        if f.stem not in completed_ids:
            with open(f, 'r') as fp:
                pending.append(json.load(fp))
    
    return pending, len(completed), len(all_files)


@app.route('/')
def index():
    """Main annotation interface."""
    pending, completed, total = get_pending_cves()
    
    if not pending:
        return "<h1>🎉 All CVEs annotated!</h1><a href='/export'>View Export</a>"
    
    cve = pending[0]
    cve_id = cve['cve_id']
    
    # Load existing progress if any
    progress_file = OUTPUT_DIR / f"{cve_id}.progress.json"
    entities = []
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            entities = json.load(f).get('entities', [])
    
    return render_template_string(TEMPLATE, 
                                  cve=cve, 
                                  entities=entities,
                                  completed=completed,
                                  total=total)


@app.route('/add_entity/<cve_id>', methods=['POST'])
def add_entity(cve_id):
    """Add entity to current annotation."""
    text = request.form.get('text', '').strip()
    entity_type = request.form.get('entity_type')
    normalized = request.form.get('normalized', '').strip() or text
    confidence = int(request.form.get('confidence', 5))
    
    # Load or create progress
    progress_file = OUTPUT_DIR / f"{cve_id}.progress.json"
    data = {'entities': []}
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            data = json.load(f)
    
    # Add entity
    data['entities'].append({
        'id': f"T{len(data['entities'])+1}",
        'type': entity_type,
        'text': text,
        'normalized': normalized,
        'confidence': confidence
    })
    
    # Save progress
    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(progress_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    return redirect('/')


@app.route('/remove_entity/<cve_id>/<int:index>', methods=['POST'])
def remove_entity(cve_id, index):
    """Remove entity from annotation."""
    progress_file = OUTPUT_DIR / f"{cve_id}.progress.json"
    
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            data = json.load(f)
        
        if 0 <= index < len(data.get('entities', [])):
            data['entities'].pop(index)
            
            # Renumber entities
            for i, e in enumerate(data['entities']):
                e['id'] = f"T{i+1}"
            
            with open(progress_file, 'w') as f:
                json.dump(data, f, indent=2)
    
    return redirect('/')


@app.route('/save/<cve_id>', methods=['POST'])
def save_annotation(cve_id):
    """Save completed annotation."""
    # Load CVE data
    with open(ANNOTATIONS_DIR / f"{cve_id}.json", 'r') as f:
        cve_data = json.load(f)
    
    # Load progress
    progress_file = OUTPUT_DIR / f"{cve_id}.progress.json"
    entities = []
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            entities = json.load(f).get('entities', [])
    
    # Build annotation
    annotation = {
        'cve_id': cve_id,
        'description': cve_data['description'],
        'metadata': {
            'annotator': ANNOTATOR_NAME,
            'annotation_date': datetime.now().isoformat(),
            'duration_minutes': None,  # Could track this
            'confidence_avg': sum(e['confidence'] for e in entities) / len(entities) if entities else 0
        },
        'entities': entities,
        'relations': [],  # Simplified - could add relation annotation
        'axioms': []
    }
    
    # Save final annotation
    with open(OUTPUT_DIR / f"{cve_id}.json", 'w') as f:
        json.dump(annotation, f, indent=2)
    
    # Clean up progress file
    if progress_file.exists():
        progress_file.unlink()
    
    return redirect('/')


@app.route('/skip/<cve_id>')
def skip_cve(cve_id):
    """Skip current CVE."""
    # Just redirect to next (progress file will be abandoned)
    return redirect('/')


@app.route('/progress')
def view_progress():
    """View annotation progress."""
    pending, completed, total = get_pending_cves()
    
    html = f"""
    <h1>Annotation Progress</h1>
    <p>Completed: {completed} / {total} ({completed/total*100:.1f}%)</p>
    <p>Remaining: {len(pending)}</p>
    <hr>
    <h2>Pending CVEs:</h2>
    <ul>
    """
    for cve in pending[:20]:  # Show first 20
        html += f"<li>{cve['cve_id']}</li>"
    if len(pending) > 20:
        html += f"<li>... and {len(pending)-20} more</li>"
    
    html += "</ul><hr><a href='/'>Back to Annotation</a>"
    return html


@app.route('/export')
def export_annotations():
    """Export all annotations as gold standard."""
    annotations = []
    for f in sorted(OUTPUT_DIR.glob('CVE-*.json')):
        if not f.name.endswith('.progress.json'):
            with open(f, 'r') as fp:
                annotations.append(json.load(fp))
    
    # Build gold standard
    gold_standard = {
        'metadata': {
            'dataset_name': 'CyberRule Gold Standard 2023',
            'version': '1.0.0',
            'creation_date': datetime.now().isoformat(),
            'total_cves': len(annotations),
            'total_entities': sum(len(a['entities']) for a in annotations),
            'annotators': list(set(a['metadata']['annotator'] for a in annotations)),
            'sampling_manifest': 'annotations/sampling_manifest.json'
        },
        'annotations': annotations
    }
    
    # Save
    with open('annotations/gold_standard_314.json', 'w') as f:
        json.dump(gold_standard, f, indent=2)
    
    return f"""
    <h1>✅ Export Complete</h1>
    <p>Exported {len(annotations)} annotations</p>
    <p>Saved to: annotations/gold_standard_314.json</p>
    <hr>
    <a href='/'>Continue Annotating</a>
    """


if __name__ == '__main__':
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Starting annotation server...")
    print(f"Annotator: {ANNOTATOR_NAME}")
    print(f"Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
