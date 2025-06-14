"""Module for loading and managing Palo Alto Networks rulebase configuration."""

from typing import Dict, Optional, List, Tuple
import xml.etree.ElementTree as ET
import json
from dataclasses import dataclass
from enum import Enum


class RuleSource(Enum):
    PANORAMA = "panorama"
    LOCAL = "local"
    SHARED = "shared"


@dataclass
class RuleInfo:
    name: str
    source: RuleSource
    device_group: Optional[str]  # For Panorama rules
    rulebase: str  # 'pre', 'post', or 'local'
    log_forwarding_profile: Optional[str]
    log_start: bool
    log_end: bool
    forwarding_enabled: bool


class RulebaseLoader:
    def __init__(self):
        self.rules: Dict[str, RuleInfo] = {}
        self.panorama_config: Optional[str] = None
        self.local_config: Optional[str] = None
        
    def load_configs(self, panorama_path: Optional[str] = None, local_path: Optional[str] = None) -> None:
        """Load both Panorama and local firewall configurations."""
        if panorama_path:
            self.panorama_config = panorama_path
            self._load_panorama_config(panorama_path)
        
        if local_path:
            self.local_config = local_path
            self._load_local_config(local_path)
            
    def _load_panorama_config(self, xml_path: str) -> None:
        """Load Panorama configuration including device groups and shared policies."""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Load shared policies first
        shared = root.find('.//shared/pre-rulebase/security/rules')
        if shared is not None:
            self._process_rules(shared, RuleSource.SHARED, None, 'pre')
            
        shared_post = root.find('.//shared/post-rulebase/security/rules')
        if shared_post is not None:
            self._process_rules(shared_post, RuleSource.SHARED, None, 'post')
        
        # Load device group policies
        device_groups = root.findall('.//device-group')
        for dg in device_groups:
            dg_name = dg.get('name')
            
            # Pre-rulebase
            pre_rules = dg.find('.//pre-rulebase/security/rules')
            if pre_rules is not None:
                self._process_rules(pre_rules, RuleSource.PANORAMA, dg_name, 'pre')
            
            # Post-rulebase
            post_rules = dg.find('.//post-rulebase/security/rules')
            if post_rules is not None:
                self._process_rules(post_rules, RuleSource.PANORAMA, dg_name, 'post')
                
    def _load_local_config(self, xml_path: str) -> None:
        """Load local firewall configuration."""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Load local rulebase
        rulebase = root.find('.//rulebase/security/rules')
        if rulebase is not None:
            self._process_rules(rulebase, RuleSource.LOCAL, None, 'local')
            
    def _process_rules(self, rules_elem: ET.Element, source: RuleSource, 
                       device_group: Optional[str], rulebase: str) -> None:
        """Process rules from an XML element."""
        for rule in rules_elem.findall('entry'):
            rule_name = rule.get('name', '')
            log_settings = rule.find('log-setting')
            log_start = rule.find('log-start')
            log_end = rule.find('log-end')
            
            # Create a rule key that includes device group for uniqueness
            rule_key = f"{device_group}::{rule_name}" if device_group else rule_name
            
            rule_info = RuleInfo(
                name=rule_name,
                source=source,
                device_group=device_group,
                rulebase=rulebase,
                log_forwarding_profile=log_settings.text if log_settings is not None else None,
                log_start=log_start is not None and log_start.text.lower() == 'yes',
                log_end=log_end is not None and log_end.text.lower() == 'yes',
                forwarding_enabled=log_settings is not None
            )
            
            # Only assign RuleSource.LOCAL if parsing an actual local firewall config (never here)
            # Always tag Panorama rules with device_group and PANORAMA source
            if source == RuleSource.PANORAMA:
                self.rules[rule_key] = rule_info
            elif source == RuleSource.SHARED:
                self.rules[rule_key] = rule_info
            # Do not allow local rules in Panorama config context
                    
    def _get_device_group_key(self, rule_name: str, dg_levels: List[str]) -> str:
        """Create a key for a rule using its device group hierarchy."""
        # Filter out empty DG levels and create the full path
        dg_path = [dg for dg in dg_levels if dg and str(dg).strip()]
        if dg_path:
            return f"{dg_path[-1]}::{rule_name}"  # Use the most specific DG
        return rule_name
        
    def get_rule_by_log_entry(self, rule_name: str, event: Dict) -> Optional[RuleInfo]:
        """Get rule info using both the rule name and the log entry's device group info."""
        # Extract device group hierarchy from the log entry
        dg_levels = [
            event.get(f'DG Hierarchy Level {i}', '')
            for i in range(1, 5)  # Levels 1-4
        ]
        
        # Try to find the rule using the device group hierarchy
        rule_key = self._get_device_group_key(rule_name, dg_levels)
        rule = self.rules.get(rule_key)
        
        # If not found with device group, try without
        if rule is None:
            rule = self.rules.get(rule_name)
            
        return rule
        
    def load_from_xml(self, xml_path: str, is_panorama: bool = False) -> None:
        """Load rulebase from a Palo Alto Networks XML configuration file.
        
        This is a compatibility method for older code. Prefer using load_configs instead.
        """
        if is_panorama:
            self._load_panorama_config(xml_path)
        else:
            self._load_local_config(xml_path)
            
    def load_from_json(self, json_path: str) -> None:
        """Load rulebase from a JSON file (useful for testing or alternative formats)."""
        with open(json_path, 'r') as f:
            self.rules = json.load(f)
            
    def get_rule_by_name(self, rule_name: str) -> Optional[Dict]:
        """Get rule details by name."""
        rule = self.rules.get(rule_name)
        if rule is None:
            return None
        return {
            'name': rule.name,
            'source': rule.source.value,
            'device_group': rule.device_group,
            'rulebase': rule.rulebase,
            'log_forwarding_profile': rule.log_forwarding_profile,
            'log_start': rule.log_start,
            'log_end': rule.log_end,
            'forwarding_enabled': rule.forwarding_enabled
        }
        
    def get_rule_forwarding_status(self, rule_name: str) -> bool:
        """Get the log forwarding status for a specific rule."""
        rule = self.rules.get(rule_name)
        if rule is None:
            # If we don't find the rule, assume forwarding is enabled by default
            # This is safer than assuming it's disabled
            return True
        return rule.forwarding_enabled
        
    def get_rule_source(self, rule_name: str) -> Optional[Tuple[RuleSource, Optional[str], str]]:
        """Get the source (Panorama/Local) and context (device group, rulebase) for a rule."""
        rule = self.rules.get(rule_name)
        if rule is None:
            return None
        return (rule.source, rule.device_group, rule.rulebase)
        
    def get_rule_details(self, rule_name: str) -> Optional[RuleInfo]:
        """Get full details for a specific rule."""
        return self.rules.get(rule_name)
