"""Configuration settings for PanLogs Analyzer."""

import os
from typing import Dict

# Directory structure
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Configuration paths
PANORAMA_CONFIG_DIR = os.path.join(CONFIG_DIR, 'panorama')
FIREWALL_CONFIG_DIR = os.path.join(CONFIG_DIR, 'firewalls')

# Log paths
LOG_DIR = os.path.join(DATA_DIR, 'logs')
TRAINING_LOG_DIR = os.path.join(LOG_DIR, 'training')
PRODUCTION_LOG_DIR = os.path.join(LOG_DIR, 'production')

# Model and state paths
MODELS_DIR = os.path.join(DATA_DIR, 'models')
STATE_DIR = os.path.join(DATA_DIR, 'state')

# Ensure all directories exist
for directory in [PANORAMA_CONFIG_DIR, FIREWALL_CONFIG_DIR, TRAINING_LOG_DIR, 
                PRODUCTION_LOG_DIR, MODELS_DIR, STATE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Log source settings
LOG_SOURCES: Dict = {
    "type": "panorama",  # or "firewall"
    "input_format": "csv",  # or "csv", "json"
    "input_path": PRODUCTION_LOG_DIR,  # Directory for production logs
    "training_path": TRAINING_LOG_DIR,  # Directory for training data
}

# AI model settings
MODEL_SETTINGS = {
    "training_sample_size": 10000,
    "feature_importance_threshold": 0.05,
    "model_update_frequency": "24h",  # How often to retrain the model
}

# SIEM forwarding settings
SIEM_SETTINGS = {
    "confidence_threshold": 0.8,  # Minimum confidence score to forward to SIEM
    "priority_levels": ["critical", "high"],  # Priority levels to always forward
}

# Storage settings
STORAGE_SETTINGS = {
    "retention_period_days": 365,
    "compression_ratio": 0.3,  # Estimated compression ratio
    "storage_buffer": 1.2,  # 20% buffer for storage calculations
}
