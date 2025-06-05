"""Configuration settings for PanLogs Analyzer."""

# Log source settings
LOG_SOURCES = {
    "type": "panorama",  # or "firewall"
    "input_format": "csv",  # or "csv", "json"
    "input_path": "logs/panorama/",  # Directory or file path
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
