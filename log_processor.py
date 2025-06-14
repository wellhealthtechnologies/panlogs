"""Module for processing Palo Alto logs."""

import pandas as pd
from datetime import datetime
from typing import Dict, Generator, List, Optional
import json
import os

class LogProcessor:
    def __init__(self, config: Dict):
        self.config = config
        self.total_events = 0
        self.total_size = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.sample_duration_hours = 0
        
        # Initialize stats
        self.event_stats = {
            'total_events': 0,
            'forwarded_events': 0,
            'total_size_gb': 0
        }
        
        # Initialize AI model with configuration
        from ai_analyzer import LogAnalyzer
        from config import MODEL_SETTINGS, SIEM_SETTINGS, MODELS_DIR
        
        # Combine model and SIEM settings
        ai_config = {
            **MODEL_SETTINGS,
            **SIEM_SETTINGS,
            'model_dir': MODELS_DIR,
            'vectorizer_path': os.path.join(MODELS_DIR, 'vectorizer.joblib'),
            'model_path': os.path.join(MODELS_DIR, 'log_analyzer_model.joblib')
        }
        self.ai_model = LogAnalyzer(ai_config)
        if not self.ai_model.load_model():
            print("Warning: No trained model found, all events will be forwarded by default")

    def process_log_file(self, file_path: str) -> Generator[Dict, None, None]:
        """Process a single log file and yield parsed events."""
        if self.config["input_format"].lower() == "syslog":
            yield from self._process_syslog(file_path)
        elif self.config["input_format"].lower() == "csv":
            yield from self._process_csv(file_path)
        elif self.config["input_format"].lower() == "json":
            yield from self._process_json(file_path)
        else:
            print(f"Warning: Unknown input format {self.config['input_format']}, trying CSV")
            yield from self._process_csv(file_path)

    def _process_syslog(self, file_path: str) -> Generator[Dict, None, None]:
        """Process syslog format files."""
        with open(file_path, 'r') as f:
            for line in f:
                # Track file size for storage calculations
                self.total_size += len(line.encode('utf-8'))
                
                # Parse syslog format
                try:
                    # Basic syslog parsing - expand based on your format
                    timestamp = line[:15]
                    message = line[16:]
                    
                    parsed_event = {
                        'timestamp': timestamp,
                        'message': message,
                        'source': file_path,
                        'size_bytes': len(line.encode('utf-8'))
                    }
                    
                    self.event_counts.append(datetime.strptime(timestamp, '%b %d %H:%M:%S'))
                    yield parsed_event
                except Exception as e:
                    print(f"Error processing line: {e}")
                    continue



    def _process_csv(self, file_path: str) -> Generator[Dict, None, None]:
        """Process CSV format files."""
        print(f"Processing {file_path}...")
        
        # First pass: determine time range and find timestamp field
        print("Analyzing log file...")
        df = pd.read_csv(file_path)
        self.total_events = len(df)
        
        # Try different timestamp column names
        timestamp_fields = ['Receive Time', 'ReceiveTime', 'Time', 'Timestamp', 'EventTime']
        timestamp_field = None
        
        for field in timestamp_fields:
            if field in df.columns:
                try:
                    timestamps = pd.to_datetime(df[field])
                    self.start_time = timestamps.min()
                    self.end_time = timestamps.max()
                    timestamp_field = field
                    break
                except:
                    continue
        
        if not timestamp_field:
            raise ValueError("No valid timestamp column found in CSV")
            
        if self.start_time and self.end_time:
            time_range = self.end_time - self.start_time
            self.sample_duration_hours = time_range.total_seconds() / 3600
            print(f"Sample duration: {self.sample_duration_hours:.2f} hours")
            print(f"Start time: {self.start_time}")
            print(f"End time: {self.end_time}")

        # Process events in larger batches for better performance
        batch_size = 10000
        total_processed = 0
        
        # Convert DataFrame to records for faster processing
        events = df.to_dict('records')
        
        # Process in batches
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            self.process_events_batch(batch)
            total_processed += len(batch)
            
            # Print progress
            if total_processed % 50000 == 0:
                print(f"Progress: Processed {total_processed:,} events...")
            
            # Yield events for further processing
            yield from batch



    def _should_forward_event(self, event: Dict) -> bool:
        """Determine if an event should be forwarded to SIEM based on AI model prediction."""
        # First check if event has explicit forwarding flag
        for field in ['LogForwarding', 'ForwardingEnabled', 'SendToSiem']:
            if field in event:
                value = str(event[field]).lower()
                if value in ('false', '0', 'disabled', 'no'):
                    return False
                elif value in ('true', '1', 'enabled', 'yes'):
                    return True
        
        # If no explicit flag, use AI model to predict
        if hasattr(self, 'ai_model') and self.ai_model is not None:
            # The predict method returns a list of tuples (should_forward, confidence)
            # We only have one event, so get the first result
            prediction = self.ai_model.predict([event])[0]
            return prediction[0]  # Return the should_forward boolean
            
        # If no AI model available, forward by default
        return True

    def _process_json(self, file_path: str) -> Generator[Dict, None, None]:
        """Process JSON format files."""
        with open(file_path, 'r') as f:
            for line in f:
                self.total_size += len(line.encode('utf-8'))
                yield json.loads(line)

    def process_events_batch(self, events: List[Dict]):
        """Process a batch of events."""
        if not events:
            return
            
        # Calculate total size of events in batch
        batch_size = 0
        forwarded = 0
        
        # Get predictions for all events in batch
        predictions = self.ai_model.predict(events) if hasattr(self, 'ai_model') else [(True, 1.0)] * len(events)
        
        # Process each event
        for event, (should_forward, confidence) in zip(events, predictions):
            # Update total size
            event_size = len(str(event).encode('utf-8'))
            batch_size += event_size
            
            # Update forwarding count
            if should_forward:
                forwarded += 1
        
        # Update stats
        self.event_stats['total_events'] += len(events)
        self.event_stats['forwarded_events'] += forwarded
        self.event_stats['total_size_gb'] += batch_size / (1024 * 1024 * 1024)
        
        # Print batch stats
        print(f"Batch complete: {forwarded:,} out of {len(events):,} events will be forwarded ({(forwarded/len(events)*100):.1f}% forwarding rate)")

    def calculate_eps(self) -> float:
        """Calculate average events per second."""
        if self.sample_duration_hours > 0:
            return self.event_stats['total_events'] / (self.sample_duration_hours * 3600)
        return 0.0
    
    def calculate_forwarded_eps(self) -> float:
        """Calculate average forwarded events per second."""
        if self.sample_duration_hours > 0:
            return self.event_stats['forwarded_events'] / (self.sample_duration_hours * 3600)
        return 0.0

    def estimate_storage(self, retention_days: int) -> Dict:
        """Calculate estimated storage requirements."""
        if not self.start_time or not self.end_time:
            print("Warning: No valid timestamps found in logs")
            return {
                'daily_size_bytes': 0,
                'retention_days': retention_days,
                'total_size_bytes': 0,
                'total_size_gb': 0
            }

        # Calculate sample duration in hours from first to last event
        hours_in_day = 24
        scaling_factor = hours_in_day / self.sample_duration_hours

        # Get stats
        total_events = self.event_stats['total_events']
        forwarded_events = self.event_stats['forwarded_events']
        total_size = self.total_size

        # Estimate daily values
        avg_daily_size = total_size * scaling_factor
        avg_daily_events = total_events * scaling_factor
        avg_daily_forwarded = forwarded_events * scaling_factor

        # Print detailed metrics
        print(f"\nSample Analysis:")
        print(f"Duration: {self.sample_duration_hours:.2f} hours")
        print(f"Total Events: {total_events:,}")
        print(f"Forwarded Events: {forwarded_events:,}")
        print(f"Filtering Efficiency: {((total_events - forwarded_events) / total_events * 100):.1f}% reduction")
        
        print(f"\nDaily Estimates (scaled from {self.sample_duration_hours:.2f} hour sample):")
        print(f"Events per Day: {avg_daily_events:,.0f}")
        print(f"Forwarded Events per Day: {avg_daily_forwarded:,.0f}")
        print(f"Events per Second (EPS): {self.calculate_eps():.1f}")
        print(f"Forwarded EPS: {self.calculate_forwarded_eps():.1f}")
        print(f"SIEM Savings: {self.calculate_eps() - self.calculate_forwarded_eps():.1f} EPS reduction")
        
        compression_ratio = self.config.get('compression_ratio', 0.3)
        buffer = self.config.get('storage_buffer', 1.2)
        
        estimated_size = (
            avg_daily_size * 
            retention_days * 
            compression_ratio * 
            buffer
        )
        
        return {
            'daily_size_bytes': avg_daily_size,
            'retention_days': retention_days,
            'total_size_bytes': estimated_size,
            'total_size_gb': estimated_size / (1024**3)
        }
