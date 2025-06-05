"""Main entry point for PanLogs Analyzer."""

import os
from typing import List, Dict
from config import LOG_SOURCES, MODEL_SETTINGS, SIEM_SETTINGS, STORAGE_SETTINGS
from log_processor import LogProcessor
from ai_analyzer import LogAnalyzer

def main():
    # Initialize components
    log_processor = LogProcessor(LOG_SOURCES)
    ai_analyzer = LogAnalyzer({**MODEL_SETTINGS, **SIEM_SETTINGS})
    
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
        for event in log_processor.process_log_file(file_path):
            events.append(event)
            
            # Analyze in batches of 1000 events
            if len(events) >= 1000:
                process_events_batch(events, ai_analyzer, log_processor)
                events = []
        
        # Process remaining events
        if events:
            process_events_batch(events, ai_analyzer, log_processor)
    
    # Calculate and display metrics
    eps = log_processor.calculate_eps()
    storage_estimate = log_processor.estimate_storage(
        STORAGE_SETTINGS['retention_period_days']
    )
    
    print("\nAnalysis Results:")
    print(f"Average Events per Second: {eps:.2f}")
    print("\nStorage Estimates:")
    print(f"Daily Size: {storage_estimate['daily_size_bytes'] / (1024**2):.2f} MB")
    print(f"Total Size for {storage_estimate['retention_days']} days: "
          f"{storage_estimate['total_size_gb']:.2f} GB")

def process_events_batch(events: List[Dict], ai_analyzer: LogAnalyzer, log_processor: LogProcessor):
    """Process a batch of events through the AI analyzer."""
    predictions = ai_analyzer.predict(events)
    
    # Count events to be forwarded
    forward_count = sum(1 for pred, _ in predictions if pred)
    log_processor.forwarded_events += forward_count
    
    # In a real implementation, you would forward the selected events to your SIEM
    if len(events) > 0:
        print(f"Batch: Forwarding {forward_count} out of {len(events)} events to SIEM")

if __name__ == "__main__":
    main()
