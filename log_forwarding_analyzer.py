"""Module for analyzing log forwarding rules and generating recommendations."""

from typing import Dict, Optional, List
from dataclasses import dataclass
from datetime import datetime
import pandas as pd
from rulebase_loader import RulebaseLoader, RuleSource
import math

@dataclass
class RuleAnalysis:
    rule_name: str
    rule_id: str
    total_eps: float
    forwarding_enabled: bool
    potential_eps_savings: float
    recommendation: str
    traffic_split_needed: bool
    excluded_traffic_eps: float
    included_traffic_eps: float
    rule_source: str  # 'panorama', 'local', or 'shared'
    device_group: Optional[str]  # For Panorama rules
    rulebase: str  # 'pre', 'post', or 'local'


class LogForwardingAnalyzer:
    def __init__(self, rulebase_path: Optional[str] = None):
        self.rule_stats: Dict[str, Dict] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.rulebase = RulebaseLoader()
        if rulebase_path:
            if rulebase_path.endswith('.xml'):
                self.rulebase.load_from_xml(rulebase_path)
            elif rulebase_path.endswith('.json'):
                self.rulebase.load_from_json(rulebase_path)
            else:
                raise ValueError("Rulebase file must be either .xml or .json")

    def process_event(self, event: Dict):
        """Process a single event and update rule statistics."""
        rule_id = self._get_rule_id(event)
        if not rule_id:
            return

        # Initialize rule stats if not exists
        if rule_id not in self.rule_stats:
            rule_name = self._get_rule_name(event)
            # Try to find device_group and rulebase from rulebase
            device_group = None
            rulebase = None
            for key, info in self.rulebase.rules.items():
                if key.endswith(f'::{rule_name}') or key == rule_name:
                    device_group = getattr(info, 'device_group', None)
                    rulebase = getattr(info, 'rulebase', None)
                    break
            self.rule_stats[rule_id] = {
                'name': rule_name,
                'device_group': device_group,
                'rulebase': rulebase,
                'total_events': 0,
                'forwarding_enabled': self._check_forwarding_enabled(event),
                'excluded_events': 0,  # Events that don't need forwarding
                'included_events': 0,  # Events that need forwarding
                'last_timestamp': None
            }

        # Update timestamps for EPS calculation
        timestamp = self._get_timestamp(event)
        if timestamp:
            if not self.start_time or timestamp < self.start_time:
                self.start_time = timestamp
            if not self.end_time or timestamp > self.end_time:
                self.end_time = timestamp
            self.rule_stats[rule_id]['last_timestamp'] = timestamp

        # Extract traffic pattern
        pattern = {
            'source': event.get('Source', 'Any'),
            'destination': event.get('Destination', 'Any'),
            'application': event.get('Application', 'Any'),
            'service': event.get('Service', 'Any'),
            'needs_forwarding': self._event_needs_forwarding(event)
        }
        
        # Initialize patterns list if not exists
        if 'patterns' not in self.rule_stats[rule_id]:
            self.rule_stats[rule_id]['patterns'] = []
            
        # Find or create pattern
        pattern_key = f"{pattern['source']}|{pattern['destination']}|{pattern['application']}|{pattern['service']}"
        found = False
        for existing in self.rule_stats[rule_id]['patterns']:
            if (existing['source'] == pattern['source'] and
                existing['destination'] == pattern['destination'] and
                existing['application'] == pattern['application'] and
                existing['service'] == pattern['service']):
                existing['count'] = existing.get('count', 0) + 1
                found = True
                break
                
        if not found:
            pattern['count'] = 1
            self.rule_stats[rule_id]['patterns'].append(pattern)
        
        # Update event counts
        self.rule_stats[rule_id]['total_events'] += 1
        
        if pattern['needs_forwarding']:
            self.rule_stats[rule_id]['included_events'] += 1
        else:
            self.rule_stats[rule_id]['excluded_events'] += 1

    def analyze_rules(self) -> List[RuleAnalysis]:
        """Analyze rules and generate recommendations."""
        if not self.start_time or not self.end_time:
            return []

        time_range = (self.end_time - self.start_time).total_seconds()
        if time_range <= 0:
            return []

        results = []
        for rule_id, stats in self.rule_stats.items():
            total_eps = stats['total_events'] / time_range
            included_eps = stats['included_events'] / time_range
            excluded_eps = stats['excluded_events'] / time_range
            
            # Calculate potential EPS savings
            potential_savings = total_eps if not stats['forwarding_enabled'] else excluded_eps
            
            # Determine if rule needs splitting
            needs_split = (
                stats['forwarding_enabled'] and 
                included_eps > 0 and 
                excluded_eps > 0 and
                (excluded_eps / total_eps) >= 0.2  # At least 20% could be excluded
            )

            # Generate recommendation
            if not stats['forwarding_enabled']:
                recommendation = "Rule already has forwarding disabled. No action needed."
            elif needs_split:
                recommendation = (
                    f"Consider splitting rule - {excluded_eps:.1f} EPS ({(excluded_eps/total_eps)*100:.1f}%) "
                    "could be excluded from forwarding"
                )
            elif excluded_eps / total_eps > 0.9:
                recommendation = "Consider disabling forwarding - over 90% of traffic could be excluded"
            else:
                recommendation = "Keep current forwarding configuration"

            # Get rule source information
            rule_source_info = self.rulebase.get_rule_source(stats['name'])
            source = "unknown"
            device_group = None
            rulebase = "unknown"
            
            if rule_source_info:
                source = rule_source_info[0].value
                device_group = rule_source_info[1]
                rulebase = rule_source_info[2]
            
            results.append(RuleAnalysis(
                rule_name=stats['name'],
                rule_id=rule_id,
                total_eps=total_eps,
                forwarding_enabled=stats['forwarding_enabled'],
                potential_eps_savings=potential_savings,
                recommendation=recommendation,
                traffic_split_needed=needs_split,
                excluded_traffic_eps=excluded_eps,
                included_traffic_eps=included_eps,
                rule_source=source,
                device_group=device_group,
                rulebase=rulebase
            ))

        return sorted(results, key=lambda x: x.potential_eps_savings, reverse=True)

    def generate_report(self) -> str:
        """Generate a formatted report of the analysis."""
        analyses = self.analyze_rules()
        if not analyses:
            return "No rule analysis data available."

        total_current_eps = sum(a.total_eps for a in analyses if a.forwarding_enabled)
        total_potential_savings = sum(a.potential_eps_savings for a in analyses)
        
        report = [
            "\nLog Forwarding Analysis Report",
            "=============================="
            f"\nCurrent Forwarded EPS: {total_current_eps:.1f}",
            f"Potential EPS Savings: {total_potential_savings:.1f}",
            f"Potential Reduction: {(total_potential_savings/total_current_eps)*100:.1f}% of current forwarded traffic",
            "\nRule-by-Rule Analysis:",
            "--------------------"
        ]

        for analysis in analyses:
            if not analysis.forwarding_enabled:
                continue  # Skip rules that already have forwarding disabled
                
            # Format rule location info
            if analysis.rule_source == 'panorama':
                location = f"Panorama ({analysis.device_group} - {analysis.rulebase} rulebase)"
            elif analysis.rule_source == 'shared':
                location = f"Panorama (Shared - {analysis.rulebase} rulebase)"
            else:
                location = "Local Firewall"
                
            report.extend([
                f"\nRule: {analysis.rule_name} (ID: {analysis.rule_id})",
                f"Location: {location}",
                f"Current EPS: {analysis.total_eps:.1f}",
                f"Traffic requiring forwarding: {analysis.included_traffic_eps:.1f} EPS",
                f"Traffic eligible for exclusion: {analysis.excluded_traffic_eps:.1f} EPS",
                f"Recommendation: {analysis.recommendation}"
            ])

        return "\n".join(report)

    def _get_rule_id(self, event: Dict) -> Optional[str]:
        """Extract rule ID from event."""
        # First try standard fields
        for field in ['RuleId', 'Rule ID', 'SecurityRule', 'Rule']:
            if field in event:
                return str(event[field])
        return None

    def _get_rule_name(self, event: Dict) -> str:
        """Extract rule name from event."""
        # First try standard fields
        for field in ['RuleName', 'Rule Name', 'SecurityRuleName', 'Rule']:
            if field in event:
                return str(event[field])
        return "Unknown Rule"

    def _check_forwarding_enabled(self, event: Dict) -> bool:
        """Check if log forwarding is enabled for this rule."""
        # First try to get the rule name
        rule_name = self._get_rule_name(event)
        
        # Check the actual rulebase first, using device group context
        if rule_name:
            rule_info = self.rulebase.get_rule_by_log_entry(rule_name, event)
            if rule_info:
                return rule_info.forwarding_enabled
            
        # Fallback to checking the event fields if rule not found in rulebase
        for field in ['LogForwarding', 'ForwardingEnabled', 'SendToSiem']:
            if field in event:
                value = str(event[field]).lower()
                return value not in ('false', '0', 'disabled', 'no')
                
        return True  # Default to True if not specified
        
    def get_rule_by_name(self, rule_name: str) -> Optional[Dict]:
        """Get rule info by name."""
        return self.rulebase.get_rule_info(rule_name)

    def _get_timestamp(self, event: Dict) -> Optional[datetime]:
        """Extract timestamp from event."""
        timestamp_fields = ['Receive Time', 'ReceiveTime', 'Time', 'Timestamp', 'EventTime']
        for field in timestamp_fields:
            if field in event and pd.notna(event[field]):
                try:
                    return pd.to_datetime(event[field])
                except:
                    continue
        return None

    def _event_needs_forwarding(self, event: Dict) -> bool:
        """Determine if an event needs to be forwarded based on its characteristics."""
        # Always forward THREAT events
        event_type = None
        for field in ['Type', 'LogType', 'EventType']:
            if field in event:
                event_type = str(event[field]).upper()
                if event_type == 'THREAT':
                    return True

        # Check severity/priority
        for field in ['Severity', 'Priority', 'Risk']:
            if field in event:
                value = str(event[field]).lower()
                if value in ('high', 'critical', '4', '5'):
                    return True

        # Add more criteria as needed
        return False
        
    def get_analysis(self) -> List[Dict]:
        """Get analysis of log forwarding rules.
        
        Returns:
            List of dictionaries containing analysis for each rule.
        """
        if not self.start_time or not self.end_time:
            return []

        time_range = (self.end_time - self.start_time).total_seconds()
        if time_range <= 0:
            return []

        rule_analyses = []
        for rule_id, stats in self.rule_stats.items():
            # Calculate EPS values
            total_eps = stats['total_events'] / time_range
            required_eps = stats['included_events'] / time_range
            excludable_eps = stats['excluded_events'] / time_range
            
            # Calculate percentages
            excludable_percent = (excludable_eps / total_eps * 100) if total_eps > 0 else 0
            
            # Determine recommendation
            if excludable_percent > 90:
                recommendation = "Consider disabling forwarding - over 90% of traffic could be excluded"
            elif excludable_percent > 50:
                recommendation = (f"Consider splitting rule - {excludable_eps:.1f} EPS "
                                f"({excludable_percent:.1f}%) could be excluded from forwarding")
            else:
                recommendation = "Current forwarding configuration is appropriate"
            
            # Always look up rule info by rule name in the rulebase
            rule_info = None
            # Prefer lookup by device_group::rule_name if device_group is present
            rule_name = stats['name']
            device_group = stats.get('device_group')
            rulebase = stats.get('rulebase')
            if device_group:
                key = f"{device_group}::{rule_name}"
                rule_info = self.rulebase.rules.get(key)
            if not rule_info:
                # fallback: search by rule name only
                for k, info in self.rulebase.rules.items():
                    if k.endswith(f'::{rule_name}') or k == rule_name:
                        rule_info = info
                        break
            if rule_info and getattr(rule_info, 'source', None) == RuleSource.PANORAMA:
                location = getattr(rule_info, 'device_group', 'Panorama')
            elif rule_info:
                location = 'Local Firewall'
            else:
                location = 'Unknown'
            device_group = getattr(rule_info, 'device_group', 'N/A') if rule_info else 'N/A'
            rulebase = getattr(rule_info, 'rulebase', 'N/A') if rule_info else 'N/A'

            # Get traffic patterns
            traffic_patterns = []
            if 'patterns' in stats:
                for pattern in stats['patterns']:
                    traffic_patterns.append({
                        'source': pattern.get('source', 'Any'),
                        'destination': pattern.get('destination', 'Any'),
                        'application': pattern.get('application', 'Any'),
                        'service': pattern.get('service', 'Any'),
                        'eps': pattern.get('eps', 0),
                        'needs_forwarding': pattern.get('needs_forwarding', False)
                    })

            # Add model analysis for excludable traffic
            model_analysis = None
            if excludable_percent > 50:
                excludable_patterns = [p for p in traffic_patterns if not p['needs_forwarding']]
                model_analysis = []
                
                # Group patterns by application for clearer analysis
                app_groups = {}
                for pattern in excludable_patterns:
                    app = pattern['application']
                    if app not in app_groups:
                        app_groups[app] = []
                    app_groups[app].append(pattern)
                
                # Generate analysis for each application group
                for app, patterns in app_groups.items():
                    if app == 'Any':
                        continue
                        
                    total_eps = sum(p.get('eps', 0) for p in patterns)
                    sources = set(p['source'] for p in patterns if p['source'] != 'Any')
                    destinations = set(p['destination'] for p in patterns if p['destination'] != 'Any')
                    services = set(p['service'] for p in patterns if p['service'] != 'Any')
                    
                    analysis = f"- {app} traffic ({total_eps:.1f} EPS)"
                    if sources:
                        analysis += f"\n  Sources: {', '.join(sorted(sources))}"
                    if destinations:
                        analysis += f"\n  Destinations: {', '.join(sorted(destinations))}"
                    if services:
                        analysis += f"\n  Services: {', '.join(sorted(services))}"
                    
                    # Add application-specific justification
                    if app in ['dns-base', 'ntp-base']:
                        analysis += "\n  Justification: Standard infrastructure traffic, low security risk"
                    elif app in ['ssl', 'web-browsing']:
                        analysis += "\n  Justification: Standard encrypted web traffic, monitored by URL filtering"
                    elif app in ['ldap', 'kerberos', 'ms-netlogon']:
                        analysis += "\n  Justification: Standard Active Directory authentication traffic"
                    elif app == 'incomplete':
                        analysis += "\n  Justification: Incomplete connections, typically noise or scan attempts"
                    elif app == 'icmp':
                        analysis += "\n  Justification: Network diagnostic traffic, monitored by threat prevention"
                    
                    model_analysis.append(analysis)
                
                if model_analysis:
                    model_analysis_str = "\n".join(model_analysis)
                else:
                    model_analysis_str = None

            # Build rule analysis dictionary after all logic
            rule_analysis = {
                'name': stats['name'],
                'id': rule_id,
                'location': location,
                'device_group': device_group,
                'rulebase': rulebase,
                'current_eps': total_eps,
                'required_eps': required_eps,
                'excludable_eps': excludable_eps,
                'excludable_percent': excludable_percent,
                'recommendation': recommendation,
                'traffic_patterns': traffic_patterns,
            }
            if model_analysis_str:
                rule_analysis['model_analysis'] = model_analysis_str

            rule_analyses.append(rule_analysis)
        
        return rule_analyses
