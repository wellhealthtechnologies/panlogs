"""Utilities for training the log analyzer model."""

import pandas as pd
from typing import Tuple, List, Dict
import os
import json

def get_column_mapping(df: pd.DataFrame) -> dict:
    """Map standard column names to actual CSV column names."""
    # Print available columns for debugging
    print("\nAvailable columns in the CSV:")
    for col in df.columns:
        print(f"  - {col}")
    print()

    # Common variations of column names
    column_patterns = {
        'type': ['Type', 'LogType', 'Log Type', 'EventType', 'Event Type'],
        'application': ['Application', 'App', 'ApplicationName', 'Application Name'],
        'action': ['Action', 'ActionTaken', 'Action Taken'],
        'source_address': ['Source Address', 'SourceAddress', 'Source IP', 'SourceIP', 'Src IP', 'Source'],
        'destination_address': ['Destination Address', 'DestinationAddress', 'Destination IP', 'DestIP', 'Dst IP', 'Destination'],
        'receive_time': ['Receive Time', 'ReceiveTime', 'Time', 'Timestamp', 'EventTime']
    }

    mapping = {}
    for standard_name, variations in column_patterns.items():
        for col in df.columns:
            if col in variations:
                mapping[standard_name] = col
                break
        if standard_name not in mapping:
            # If no match found, try case-insensitive comparison
            for col in df.columns:
                if any(var.lower() == col.lower() for var in variations):
                    mapping[standard_name] = col
                    break
    
    return mapping

def prepare_training_data(csv_path: str, output_file: str = 'labeled_data.json') -> None:
    """
    Interactive utility to help label logs for training.
    Args:
        csv_path: Path to the Panorama CSV export
        output_file: Where to save the labeled data
    """
    # Load existing labeled data if any
    labeled_data = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            labeled_data = json.load(f)
            print(f"Loaded {len(labeled_data)} existing labeled events")

    # Read the CSV file
    df = pd.read_csv(csv_path)
    
    # Get column mapping
    col_map = get_column_mapping(df)
    
    # Skip already labeled events
    labeled_ids = set(item['id'] for item in labeled_data)
    
    # Automatically label THREAT logs
    if 'type' in col_map:
        threat_logs = df[df[col_map['type']] == 'THREAT']
    for idx, row in threat_logs.iterrows():
        event_id = f"{row.get('Receive Time', '')}_{idx}"
        if event_id not in labeled_ids:
            labeled_data.append({
                'id': event_id,
                'event': row.to_dict(),
                'forward': True,
                'auto_labeled': True
            })
    
    # Group similar non-THREAT logs
    non_threat_logs = df[df['Type'] != 'THREAT'].copy()
    if len(non_threat_logs) == 0:
        print("No non-THREAT logs to process")
        return
    
    # Create groups based on Type, Application, and Action
    def create_group_key(row):
        type_val = row.get(col_map.get('type', ''), 'N/A')
        app_val = row.get(col_map.get('application', ''), 'N/A')
        action_val = row.get(col_map.get('action', ''), 'N/A')
        return f"{type_val}|{app_val}|{action_val}"

    non_threat_logs['group_key'] = non_threat_logs.apply(create_group_key, axis=1)
    
    groups = non_threat_logs.groupby('group_key')
    print(f"\nFound {len(groups)} distinct log patterns to review")
    
    print("\nLabeling Instructions:")
    print("You'll be shown groups of similar logs. For each group, decide if logs of this type should be forwarded to SIEM.")
    print("Consider factors like:")
    print("- Type of activity")
    print("- Application importance")
    print("- Action criticality")
    print("\nEnter 'q' at any time to save and quit.\n")

    try:
        for group_key, group in groups:
            type_, app, action = group_key.split('|')
            print("\nLog Group Summary:")
            print(f"Type: {type_}")
            print(f"Application: {app}")
            print(f"Action: {action}")
            print(f"Number of logs in this group: {len(group)}")
            
            # Show a sample of source/destination if varied
            # Show sample addresses if columns exist
            if 'source_address' in col_map:
                print("\nSample source addresses:", ', '.join(str(x) for x in group[col_map['source_address']].unique()[:3]))
            if 'destination_address' in col_map:
                print("Sample destination addresses:", ', '.join(str(x) for x in group[col_map['destination_address']].unique()[:3]))
            
            while True:
                choice = input("\nShould logs of this type be forwarded to SIEM? (y/n/q): ").lower()
                if choice in ['y', 'n', 'q']:
                    break
                print("Invalid input. Please enter 'y' for yes, 'n' for no, or 'q' to quit.")

            if choice == 'q':
                break

            # Store all events from this group
            for idx, row in group.iterrows():
                event_id = f"{row.get('Receive Time', '')}_{idx}"
                if event_id not in labeled_ids:
                    labeled_data.append({
                        'id': event_id,
                        'event': row.to_dict(),
                        'forward': choice == 'y'
                    })

            # Save periodically
            if len(labeled_data) % 10 == 0:
                with open(output_file, 'w') as f:
                    json.dump(labeled_data, f, indent=2)
                print(f"\nSaved {len(labeled_data)} labeled events")

    except KeyboardInterrupt:
        print("\nLabeling interrupted by user")

    # Final save
    with open(output_file, 'w') as f:
        json.dump(labeled_data, f, indent=2)
    print(f"\nFinal save: {len(labeled_data)} labeled events")

def get_training_data(labeled_file: str = 'labeled_data.json') -> Tuple[List[Dict], List[int]]:
    """
    Load labeled data and convert it to training format.
    Returns:
        Tuple of (events, labels) for training
    """
    if not os.path.exists(labeled_file):
        raise FileNotFoundError(f"No labeled data found at {labeled_file}")

    with open(labeled_file, 'r') as f:
        labeled_data = json.load(f)

    events = [item['event'] for item in labeled_data]
    labels = [1 if item['forward'] else 0 for item in labeled_data]

    return events, labels
