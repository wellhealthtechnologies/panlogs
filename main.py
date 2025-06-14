"""Main entry point for PanLogs Analyzer."""

import os
from typing import List, Dict, Optional, Tuple
from config import (LOG_SOURCES, MODEL_SETTINGS, SIEM_SETTINGS, STORAGE_SETTINGS,
                  PANORAMA_CONFIG_DIR, FIREWALL_CONFIG_DIR)
from report_generator import ReportGenerator
from log_processor import LogProcessor
from ai_analyzer import LogAnalyzer
from log_forwarding_analyzer import LogForwardingAnalyzer

def load_configs() -> Tuple[List[str], List[str]]:
    """Load all configuration files from the config directories.
    
    Returns:
        Tuple of (panorama_configs, firewall_configs)
    """
    panorama_configs = []
    firewall_configs = []
    
    # Load Panorama configs
    if os.path.exists(PANORAMA_CONFIG_DIR):
        for file in os.listdir(PANORAMA_CONFIG_DIR):
            if file.endswith('.xml'):
                panorama_configs.append(os.path.join(PANORAMA_CONFIG_DIR, file))
                
    # Load Firewall configs
    if os.path.exists(FIREWALL_CONFIG_DIR):
        for file in os.listdir(FIREWALL_CONFIG_DIR):
            if file.endswith('.xml'):
                firewall_configs.append(os.path.join(FIREWALL_CONFIG_DIR, file))
                
    return panorama_configs, firewall_configs

def main(config_dir: Optional[str] = None):
    # Initialize components
    log_processor = LogProcessor(LOG_SOURCES)
    ai_analyzer = LogAnalyzer({**MODEL_SETTINGS, **SIEM_SETTINGS})
    forwarding_analyzer = LogForwardingAnalyzer()
    
    # Load configurations from directories
    try:
        panorama_configs, firewall_configs = load_configs()
        
        # Load all Panorama configurations
        for config in panorama_configs:
            print(f"Loading Panorama configuration from: {config}")
            forwarding_analyzer.rulebase.load_configs(panorama_path=config)
            
        # Load all Firewall configurations
        for config in firewall_configs:
            print(f"Loading Firewall configuration from: {config}")
            forwarding_analyzer.rulebase.load_configs(local_path=config)
            
        if not panorama_configs and not firewall_configs:
            print("Warning: No configurations found in config directories.")
            print("Will attempt to determine forwarding status from log data.")
            
    except Exception as e:
        print(f"Error loading configurations: {e}")
        print("Proceeding with log data analysis only.")
    
    # Check if we need to prepare training data
    if not os.path.exists('labeled_data.json'):
        print("No training data found. Let's prepare some training data first.")
        print("You'll need to label some log entries to train the model.")
        from training_utils import prepare_training_data
        
        # Get the first CSV file from the input directory
        input_path = LOG_SOURCES['input_path']
        csv_files = [f for f in os.listdir(input_path) if f.endswith('.csv')]
        if not csv_files:
            print("Error: No CSV files found in the input directory!")
            return
        
        csv_path = os.path.join(input_path, csv_files[0])
        prepare_training_data(csv_path)
    
    # Load or train the model
    if not ai_analyzer.load_model():
        print("Training new model...")
        from training_utils import get_training_data
        try:
            training_events, labels = get_training_data()
            ai_analyzer.train(training_events, labels)
            print("Model trained successfully!")
        except FileNotFoundError:
            print("Error: No labeled training data found!")
            return
    
    # Process logs
    input_path = LOG_SOURCES['input_path']
    if os.path.isdir(input_path):
        files = [os.path.join(input_path, f) for f in os.listdir(input_path)]
    else:
        files = [input_path]
    
    # Process each log file
    for file_path in files:
        print(f"Processing {file_path}...")
        events = []
        batch_count = 0
        for event in log_processor.process_log_file(file_path):
            events.append(event)
            
            # Analyze in batches of 1000 events
            if len(events) >= 1000:
                process_events_batch(events, ai_analyzer, log_processor, forwarding_analyzer)
                events = []
                batch_count += 1
                if batch_count >= 2:  # Stop after 2 batches
                    print("\nStopping after 2 batches for testing...")
                    break
        
        # Process remaining events if we haven't hit batch limit
        if events and batch_count < 2:
            process_events_batch(events, ai_analyzer, log_processor, forwarding_analyzer)
        
        # Break out of file processing loop too
        if batch_count >= 2:
            break
    
    # Calculate and display metrics
    eps = log_processor.calculate_eps()
    storage_estimate = log_processor.estimate_storage(
        STORAGE_SETTINGS['retention_period_days']
    )
    
    # Generate reports
    report_gen = ReportGenerator()
    
    # Archive any previous reports
    report_gen.archive_previous_reports()
    
    # Get stats
    total_events = log_processor.event_stats['total_events']
    forwarded_events = log_processor.event_stats['forwarded_events']
    
    # Prepare sample analysis data
    sample_analysis = {
        'duration': log_processor.sample_duration_hours,
        'total_events': total_events,
        'forwarded_events': forwarded_events,
        'filtering_efficiency': ((total_events - forwarded_events) 
                               / total_events * 100 if total_events > 0 else 0)
    }
    
    # Prepare daily estimates
    daily_estimates = {
        'events_per_day': total_events * (24 / log_processor.sample_duration_hours) 
                         if log_processor.sample_duration_hours > 0 else 0,
        'forwarded_per_day': forwarded_events * (24 / log_processor.sample_duration_hours)
                            if log_processor.sample_duration_hours > 0 else 0,
        'eps': log_processor.calculate_eps(),
        'forwarded_eps': log_processor.calculate_forwarded_eps(),
        'siem_savings': log_processor.calculate_eps() - log_processor.calculate_forwarded_eps()
    }
    
    # Get storage estimates
    storage_estimates = log_processor.estimate_storage(STORAGE_SETTINGS['retention_period_days'])
    storage_estimates['daily_size_gb'] = storage_estimates['daily_size_bytes'] / (1024**3)
    
    # Generate summary report
    summary_report = report_gen.generate_summary_report(
        sample_analysis,
        daily_estimates,
        storage_estimates
    )
    
    # Get forwarding analysis
    rules_analysis = forwarding_analyzer.get_analysis()
    
    # Generate forwarding report
    forwarding_report = report_gen.generate_forwarding_report(rules_analysis)
    
    print(f"\nReports generated:")
    print(f"Summary Report: {summary_report}")
    print(f"Forwarding Analysis: {forwarding_report}")

def process_events_batch(events: List[Dict], ai_analyzer: LogAnalyzer, log_processor: LogProcessor, forwarding_analyzer: LogForwardingAnalyzer):
    """Process a batch of events through the AI analyzer."""
    predictions = ai_analyzer.predict(events)
    
    # Count events to be forwarded
    forward_count = sum(1 for pred, _ in predictions if pred)
    
    # Update forwarded events count in log processor
    log_processor.event_stats['forwarded_events'] += forward_count
    
    # Process each event through the forwarding analyzer
    for event in events:
        forwarding_analyzer.process_event(event)
    
    # In a real implementation, you would forward the selected events to your SIEM
    if len(events) > 0:
        print(f"Batch: Forwarding {forward_count:,} out of {len(events):,} events to SIEM")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PanLogs Analyzer')
    parser.add_argument('--config-dir', type=str, help='Optional: override default config directory')
    
    args = parser.parse_args()
    main(args.config_dir)
