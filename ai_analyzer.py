"""AI-based log analysis module."""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from typing import Dict, List, Tuple
import joblib
import os

class LogAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_importance_threshold = config['feature_importance_threshold']
        
    def prepare_features(self, events: List[Dict]) -> np.ndarray:
        """Convert log events into feature vectors."""
        # Extract relevant fields from events
        texts = []
        for event in events:
            # Create a comprehensive text representation of the event
            event_parts = []
            for key, value in event.items():
                if value and str(value).strip() and not key.endswith('Time'):
                    event_parts.append(f"{key}:{str(value).strip()}")
            texts.append(' '.join(event_parts))
        
        # Transform texts into TF-IDF features
        if not texts:
            raise ValueError("No valid text features found in the events")
        
        # Configure vectorizer to handle the data better
        self.vectorizer.min_df = 1  # Include terms that appear at least once
        self.vectorizer.max_features = None  # Don't limit features
        self.vectorizer.stop_words = None  # Don't remove stop words
        
        return self.vectorizer.fit_transform(texts)

    def train(self, events: List[Dict], labels: List[int]):
        """Train the AI model on historical data."""
        X = self.prepare_features(events)
        X_train, X_val, y_train, y_val = train_test_split(
            X, labels, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        val_score = self.model.score(X_val, y_val)
        print(f"Validation accuracy: {val_score:.2f}")
        
        # Save model
        self._save_model()

    def predict(self, events: List[Dict]) -> List[Tuple[bool, float]]:
        """Predict which events should be forwarded to SIEM."""
        # First check for THREAT type events
        results = []
        for event in events:
            # Check if it's a THREAT event (try different possible field names)
            is_threat = False
            event_type = None
            for field in ['Type', 'LogType', 'EventType']:
                if field in event:
                    event_type = str(event[field]).upper()
                    if event_type == 'THREAT':
                        is_threat = True
                        break
            
            if is_threat:
                results.append((True, 1.0))  # Always forward THREAT events with 100% confidence
                continue
            
            # For non-THREAT events, use the AI model
            # Create feature text from all available fields
            feature_text = ' '.join(
                f"{k}:{str(v)}"
                for k, v in event.items()
                if v and str(v).strip() and not k.endswith('Time')
            )
            
            # Transform single event
            X = self.vectorizer.transform([feature_text])
        
            # Get prediction and probability for this event
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]
            confidence = probability[1] if prediction == 1 else probability[0]
            
            # Determine if we should forward based on confidence and rules
            should_forward = (
                confidence >= self.config['confidence_threshold'] or
                self._check_priority_rules(event)
            )
            results.append((should_forward, confidence))
            
        return results

    def _check_priority_rules(self, event: Dict) -> bool:
        """Check if event matches priority forwarding rules."""
        # Check priority/severity levels
        priority_levels = self.config.get('priority_levels', [])
        for field in ['Severity', 'Priority', 'Risk']:
            if field in event:
                event_priority = str(event[field]).lower()
                if event_priority in priority_levels:
                    return True
        
        # Additional rules can be added here
        # For example, check for specific applications, actions, or other criteria
        return False

    def _save_model(self):
        """Save the trained model and vectorizer."""
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, 'models/log_analyzer_model.joblib')
        joblib.dump(self.vectorizer, 'models/vectorizer.joblib')

    def load_model(self):
        """Load a previously trained model."""
        if os.path.exists('models/log_analyzer_model.joblib'):
            self.model = joblib.load('models/log_analyzer_model.joblib')
            self.vectorizer = joblib.load('models/vectorizer.joblib')
            return True
        return False
