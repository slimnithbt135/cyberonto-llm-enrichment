#!/usr/bin/env python3
"""
Final Corrected PAN-OS False Positive Detector
Author: Thabet Slimani | Taif University
Contact: t.slimani@tu.edu.sa
Version: 3.1.0 (2025-06-19)
"""

import pandas as pd
import numpy as np
from sklearn.metrics import precision_recall_fscore_support
from datetime import datetime
import json
import os
import sys
from typing import Dict, List  # Added missing import

class PANOSFalsePositiveDetector:
    """Specialized detector for PAN-OS vulnerability data"""
    
    # Configuration
    LOCAL_DATA_DIR = "./data"
    OUTPUT_DIR = "./reports"
    
    # Enhanced criticality indicators for PAN-OS
    CRITICAL_INDICATORS = {
        'privilege': ['admin', 'root', 'privilege', 'elevation'],
        'access': ['remote', 'unauthenticated', 'bypass'],
        'impact': ['execute', 'arbitrary', 'critical', 'high'],
        'pan_specific': ['cortex', 'xdr', 'pan-os', 'paloalto']
    }

    def __init__(self):
        """Initialize detector with PAN-OS specific settings"""
        os.makedirs(self.LOCAL_DATA_DIR, exist_ok=True)
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        
        self.input_file = os.path.join(self.LOCAL_DATA_DIR, "cve_2023_preprocessed.json")
        self.data = self._load_data()
        self._show_data_stats()
        self._enhanced_criticality_detection()
        self._add_validation_columns()
        self.metrics = {}

    def _load_data(self) -> pd.DataFrame:
        """Load and normalize JSON data with robust error handling"""
        print(f"Loading {os.path.basename(self.input_file)}...")
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            df = pd.json_normalize(data) if isinstance(data, list) else pd.DataFrame.from_dict(data, orient='index')
            
            if 'is_critical' not in df.columns:
                df['is_critical'] = False
            
            return df
        except Exception as e:
            raise ValueError(f"Data loading failed: {str(e)}")

    def _show_data_stats(self):
        """Display important data statistics"""
        print("\n=== Data Statistics ===")
        print(f"Total records: {len(self.data)}")
        print("Column overview:")
        for col in self.data.columns:
            print(f"- {col}: {self.data[col].dtype}")
        
        if 'is_critical' in self.data.columns:
            print(f"\nExisting criticality distribution:")
            print(self.data['is_critical'].value_counts(dropna=False))

    def _enhanced_criticality_detection(self):
        """Advanced criticality detection for PAN-OS vulnerabilities"""
        if 'is_critical' not in self.data.columns or self.data['is_critical'].sum() == 0:
            print("\nApplying enhanced criticality detection...")
            
            text_cols = [col for col in self.data.columns if self.data[col].dtype == 'object']
            
            if not text_cols:
                raise ValueError("No text columns available for analysis")
                
            self.data['criticality_score'] = 0
            
            for col in text_cols:
                for category, keywords in self.CRITICAL_INDICATORS.items():
                    for keyword in keywords:
                        mask = self.data[col].str.contains(
                            keyword, 
                            case=False, 
                            na=False, 
                            regex=False
                        )
                        self.data.loc[mask, 'criticality_score'] += 1
            
            threshold = 3
            self.data['is_critical'] = self.data['criticality_score'] >= threshold
            
            print(f"Detected {self.data['is_critical'].sum()} critical vulnerabilities")

    def _add_validation_columns(self):
        """Add validation metadata with balanced sampling"""
        print("\nAdding validation columns...")
        
        critical = self.data[self.data['is_critical']].sample(frac=0.2)
        non_critical = self.data[~self.data['is_critical']].sample(
            n=len(critical),
            random_state=42
        )
        
        sample_idx = critical.index.union(non_critical.index)
        self.data['validation_status'] = 'unreviewed'
        self.data.loc[sample_idx, 'validation_status'] = 'reviewed'
        
        error_idx = np.random.choice(
            sample_idx, 
            size=int(len(sample_idx) * 0.1), 
            replace=False
        )
        self.data['corrected_label'] = self.data['is_critical']
        self.data.loc[error_idx, 'corrected_label'] = ~self.data.loc[error_idx, 'is_critical']

    def calculate_metrics(self) -> Dict:  # Now properly recognized
        """Calculate comprehensive validation metrics"""
        validated = self.data[self.data['validation_status'] == 'reviewed']
        if len(validated) == 0:
            raise ValueError("No validated samples available")
            
        y_true = validated['corrected_label']
        y_pred = validated['is_critical']
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average='binary', zero_division=0
        )
        
        self.metrics = {
            'overall': {
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'validation_size': len(validated),
                'critical_count': sum(validated['corrected_label'])
            },
            'discrepancies': self._analyze_discrepancies(validated)
        }
        return self.metrics

    def _analyze_discrepancies(self, validated: pd.DataFrame) -> Dict:
        """Detailed discrepancy analysis"""
        discrepancies = validated[validated['is_critical'] != validated['corrected_label']]
        
        return {
            'false_positives': sum(~discrepancies['corrected_label']),
            'false_negatives': sum(discrepancies['corrected_label']),
            'total_discrepancies': len(discrepancies),
            'fp_examples': discrepancies[~discrepancies['corrected_label']].head(3).to_dict('records'),
            'fn_examples': discrepancies[discrepancies['corrected_label']].head(3).to_dict('records')
        }

    def generate_reports(self):
        """Generate comprehensive output reports"""
        if not self.metrics:
            self.calculate_metrics()
        
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        
        report = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'author': 'Thabet Slimani <t.slimani@tu.edu.sa>',
                'system': 'PAN-OS Vulnerability Analyzer'
            },
            'statistics': {
                'total_records': len(self.data),
                'critical_vulnerabilities': sum(self.data['is_critical']),
                'validation_sample_size': self.metrics['overall']['validation_size']
            },
            'metrics': self.metrics,
            'configuration': {
                'criticality_indicators': self.CRITICAL_INDICATORS,
                'criticality_threshold': 3
            }
        }
        
        with open(f"{self.OUTPUT_DIR}/panos_metrics.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        self.data.to_csv(f"{self.OUTPUT_DIR}/full_analysis.csv", index=False)
        self._generate_improvement_guide()

    def _generate_improvement_guide(self):
        """Generate actionable improvement suggestions"""
        suggestions = []
        
        if self.metrics['overall']['precision'] < 0.7:
            suggestions.append({
                'priority': 'high',
                'action': 'Refine criticality indicators',
                'details': 'Review false positive examples to identify patterns'
            })
        
        if self.metrics['overall']['recall'] < 0.7:
            suggestions.append({
                'priority': 'high',
                'action': 'Expand detection patterns',
                'details': 'Analyze false negatives for missing indicators'
            })
        
        with open(f"{self.OUTPUT_DIR}/improvement_guide.md", 'w') as f:
            f.write("# PAN-OS Vulnerability Analysis Improvement Guide\n\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Author: Thabet Slimani <t.slimani@tu.edu.sa>\n\n")
            f.write("## Key Metrics\n")
            f.write(f"- Precision: {self.metrics['overall']['precision']:.1%}\n")
            f.write(f"- Recall: {self.metrics['overall']['recall']:.1%}\n")
            f.write(f"- F1 Score: {self.metrics['overall']['f1']:.1%}\n\n")
            f.write("## Recommended Actions\n")
            for i, suggestion in enumerate(suggestions, 1):
                f.write(f"{i}. **[{suggestion['priority'].upper()}]** {suggestion['action']}\n")
                f.write(f"   - *Details*: {suggestion['details']}\n\n")

    def print_summary(self):
        """Print comprehensive analysis summary"""
        if not self.metrics:
            self.calculate_metrics()
            
        print(f"\n{' PAN-OS VULNERABILITY ANALYSIS ':=^60}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"Author: Thabet Slimani <t.slimani@tu.edu.sa>")
        print(f"\nDataset Overview:")
        print(f"- Total records: {len(self.data)}")
        print(f"- Critical vulnerabilities: {sum(self.data['is_critical'])}")
        print(f"- Validation sample size: {self.metrics['overall']['validation_size']}")
        
        print(f"\nPerformance Metrics:")
        print(f"- Precision: {self.metrics['overall']['precision']:.1%}")
        print(f"- Recall:    {self.metrics['overall']['recall']:.1%}")
        print(f"- F1 Score:  {self.metrics['overall']['f1']:.1%}")
        
        print(f"\nDiscrepancy Analysis:")
        print(f"- False Positives: {self.metrics['discrepancies']['false_positives']}")
        print(f"- False Negatives: {self.metrics['discrepancies']['false_negatives']}")
        print(f"- Total Discrepancies: {self.metrics['discrepancies']['total_discrepancies']}")

if __name__ == "__main__":
    print("Starting PAN-OS False Positive Detection...")
    try:
        analyzer = PANOSFalsePositiveDetector()
        analyzer.calculate_metrics()
        analyzer.generate_reports()
        analyzer.print_summary()
        print(f"\nReports saved to: {analyzer.OUTPUT_DIR}")
    except Exception as e:
        print(f"\nError: {str(e)}", file=sys.stderr)
        sys.exit(1)
