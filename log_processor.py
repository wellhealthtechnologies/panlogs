"""Module for processing Palo Alto logs."""

import pandas as pd
from datetime import datetime
import json
from typing import Dict, List, Generator
import os

class LogProcessor:
    def __init__(self, config: Dict):
        self.config = config
        self.event_counts = []
        self.total_size = 0
        self.start_time = None
        self.end_time = None
        self.total_events = 0
        self.forwarded_events = 0
        self.sample_duration_hours = 0.0

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
        for chunk in pd.read_csv(file_path, chunksize=1000):
            self.total_size += chunk.memory_usage(deep=True).sum()
            for _, row in chunk.iterrows():
                self.total_events += 1
                event = row.to_dict()
                
                # Try to parse timestamp from common field names
                timestamp_fields = ['Receive Time', 'ReceiveTime', 'Time', 'Timestamp', 'EventTime']
                timestamp = None
                for field in timestamp_fields:
                    if field in event and pd.notna(event[field]):
                        try:
                            timestamp = pd.to_datetime(event[field])
                            if self.start_time is None or timestamp < self.start_time:
                                self.start_time = timestamp
                            if self.end_time is None or timestamp > self.end_time:
                                self.end_time = timestamp
                            if self.start_time and self.end_time:
                                time_range = self.end_time - self.start_time
                                self.sample_duration_hours = time_range.total_seconds() / 3600
                            break
                        except Exception as e:
                            continue
                
                if timestamp:
                    self.event_counts.append(timestamp)
                
                yield event

    def _process_json(self, file_path: str) -> Generator[Dict, None, None]:
        """Process JSON format files."""
        with open(file_path, 'r') as f:
            for line in f:
                self.total_size += len(line.encode('utf-8'))
                yield json.loads(line)

    def calculate_eps(self) -> float:
        """Calculate average events per second."""
        if not self.start_time or not self.end_time:
            return 0.0
        
        time_range = self.end_time - self.start_time
        total_seconds = time_range.total_seconds()
        if total_seconds == 0:
            return 0.0

        # Scale to 24 hours if sample is shorter
        if self.sample_duration_hours < 24:
            scaling_factor = 24 / self.sample_duration_hours
            scaled_events = self.total_events * scaling_factor
            return scaled_events / (24 * 3600)
        
        return self.total_events / total_seconds

    def calculate_forwarded_eps(self) -> float:
        """Calculate average forwarded events per second."""
        if not self.start_time or not self.end_time:
            return 0.0
        
        time_range = self.end_time - self.start_time
        total_seconds = time_range.total_seconds()
        if total_seconds == 0:
            return 0.0

        # Scale to 24 hours if sample is shorter
        if self.sample_duration_hours < 24:
            scaling_factor = 24 / self.sample_duration_hours
            scaled_events = self.forwarded_events * scaling_factor
            return scaled_events / (24 * 3600)
        
        return self.forwarded_events / total_seconds

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

        # Calculate the sample duration in hours
        time_range = self.end_time - self.start_time
        self.sample_duration_hours = time_range.total_seconds() / 3600

        if self.sample_duration_hours < 1:
            print(f"Warning: Sample duration is very short ({self.sample_duration_hours:.2f} hours)")

        # Calculate daily estimates based on the sample
        hours_in_day = 24
        scaling_factor = hours_in_day / self.sample_duration_hours

        # Estimate daily values
        avg_daily_size = self.total_size * scaling_factor
        avg_daily_events = self.total_events * scaling_factor
        avg_daily_forwarded = self.forwarded_events * scaling_factor

        # Print detailed metrics
        print(f"\nSample Analysis:")
        print(f"Duration: {self.sample_duration_hours:.2f} hours")
        print(f"Total Events: {self.total_events:,}")
        print(f"Forwarded Events: {self.forwarded_events:,}")
        print(f"Filtering Efficiency: {((self.total_events - self.forwarded_events) / self.total_events * 100):.1f}% reduction")
        
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
