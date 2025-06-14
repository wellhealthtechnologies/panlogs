"""Module for generating analysis reports."""

import os
from datetime import datetime
from typing import Dict, List, Optional
import json
from config import DATA_DIR

class ReportGenerator:
    def __init__(self):
        self.reports_dir = os.path.join(DATA_DIR, 'reports')
        self.latest_dir = os.path.join(self.reports_dir, 'latest')
        self._ensure_directories()
        
    def _ensure_directories(self):
        """Ensure report directories exist."""
        os.makedirs(self.latest_dir, exist_ok=True)
        
    def _get_timestamp(self) -> str:
        """Get formatted timestamp for report names."""
        return datetime.now().strftime('%Y%m%d_%H%M%S')
        
    def generate_summary_report(self, 
                              sample_analysis: Dict,
                              daily_estimates: Dict,
                              storage_estimates: Dict) -> str:
        """Generate summary report with sample analysis and estimates."""
        timestamp = self._get_timestamp()
        filename = os.path.join(self.latest_dir, 'summary_report.txt')
        
        with open(filename, 'w') as f:
            # Sample Analysis
            f.write("Sample Analysis:\n")
            f.write("=" * 50 + "\n")
            f.write(f"Duration: {sample_analysis['duration']:.2f} hours\n")
            f.write(f"Total Events: {sample_analysis['total_events']:,}\n")
            f.write(f"Forwarded Events: {sample_analysis['forwarded_events']:,}\n")
            f.write(f"Filtering Efficiency: {sample_analysis['filtering_efficiency']:.1f}% reduction\n\n")
            
            # Daily Estimates
            f.write("Daily Estimates:\n")
            f.write("=" * 50 + "\n")
            f.write(f"Events per Day: {daily_estimates['events_per_day']:,.0f}\n")
            f.write(f"Forwarded Events per Day: {daily_estimates['forwarded_per_day']:,.0f}\n")
            f.write(f"Events per Second (EPS): {daily_estimates['eps']:.1f}\n")
            f.write(f"Forwarded EPS: {daily_estimates['forwarded_eps']:.1f}\n")
            f.write(f"SIEM Savings: {daily_estimates['siem_savings']:.1f} EPS reduction\n\n")
            
            # Storage Estimates
            f.write("Storage Estimates:\n")
            f.write("=" * 50 + "\n")
            f.write(f"Daily Size: {storage_estimates['daily_size_gb']:.2f} GB\n")
            f.write(f"Retention Period: {storage_estimates['retention_days']} days\n")
            f.write(f"Total Storage Required: {storage_estimates['total_size_gb']:.2f} GB\n")
            
        return filename
        
    def generate_forwarding_report(self, rules_analysis: List[Dict]) -> str:
        """Generate log forwarding analysis report."""
        timestamp = self._get_timestamp()
        filename = os.path.join(self.latest_dir, 'forwarding_report.txt')
        
        with open(filename, 'w') as f:
            f.write("Log Forwarding Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            for rule in rules_analysis:
                # Basic rule info
                f.write(f"Rule: {rule['name']} (ID: {rule['id']})\n")
                f.write(f"Location: {rule['location']}\n")
                if rule['device_group'] != 'N/A':
                    f.write(f"Device Group: {rule['device_group']}\n")
                if rule['rulebase'] != 'N/A':
                    f.write(f"Rulebase: {rule['rulebase']}\n")
                
                # Traffic stats
                f.write(f"Current EPS: {rule['current_eps']:.1f}\n")
                f.write(f"Traffic requiring forwarding: {rule['required_eps']:.1f} EPS\n")
                f.write(f"Traffic eligible for exclusion: {rule['excludable_eps']:.1f} EPS\n")
                f.write(f"Recommendation: {rule['recommendation']}\n")
                
                # Add traffic patterns that can be excluded
                if rule.get('traffic_patterns'):
                    excludable_patterns = [p for p in rule['traffic_patterns'] if not p.get('needs_forwarding')]
                    if excludable_patterns:
                        f.write("\nTraffic patterns that can be excluded:\n")
                        for pattern in excludable_patterns:
                            pattern_desc = []
                            if pattern['source'] != 'Any':
                                pattern_desc.append(f"from {pattern['source']}")
                            if pattern['destination'] != 'Any':
                                pattern_desc.append(f"to {pattern['destination']}")
                            if pattern['application'] != 'Any':
                                pattern_desc.append(f"using {pattern['application']}")
                            if pattern['service'] != 'Any':
                                pattern_desc.append(f"on {pattern['service']}")
                            if pattern.get('eps'):
                                pattern_desc.append(f"({pattern['eps']:.1f} EPS)")
                            f.write(f"- Traffic {' '.join(pattern_desc)}\n")
                
                # Add model analysis info
                if rule.get('model_analysis'):
                    f.write("\nModel Analysis:\n")
                    f.write(rule['model_analysis'] + "\n")
                
                f.write("\n" + "=" * 50 + "\n\n")
                
        return filename
        

        
    def archive_previous_reports(self):
        """Archive previous reports to a timestamped directory."""
        if not os.path.exists(self.latest_dir):
            return
            
        timestamp = self._get_timestamp()
        archive_dir = os.path.join(self.reports_dir, f'archive_{timestamp}')
        os.makedirs(archive_dir, exist_ok=True)
        
        for file in os.listdir(self.latest_dir):
            if file.endswith('.txt'):
                src = os.path.join(self.latest_dir, file)
                dst = os.path.join(archive_dir, file)
                os.rename(src, dst)
