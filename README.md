# PanLogs Analyzer

An AI-powered log analysis tool for Palo Alto firewalls and Panorama log collectors. This tool helps determine which logs should be forwarded to SIEM systems and provides storage sizing calculations based on retention requirements.

## Features

- AI-based log analysis for SIEM forwarding decisions using RandomForest classifier
- Intelligent log filtering based on confidence scores and priority levels
- Storage size calculation based on retention period and compression ratios
- Events per second (EPS) calculation with daily scaling
- Support for multiple log formats:
  - Syslog
  - CSV
  - JSON

## Requirements

- Python 3.11+
- scikit-learn 1.3.0 (specific version required for model compatibility)
- numpy 1.24.3
- pandas 2.0.0+
- Other dependencies as listed in requirements.txt

## Installation

1. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

```
PanLogs/
├── config/                 # Configuration files
│   ├── panorama/          # Panorama XML configurations
│   └── firewalls/         # Individual firewall XML configurations
├── data/
│   ├── logs/
│   │   ├── training/      # Logs used for training the AI model
│   │   └── production/    # Production logs to analyze
│   ├── models/            # Trained AI models
│   └── state/            # Application state and caches
└── src/                   # Source code
```

## Usage

1. Configure your settings in `config.py`:
   - Set input log format (syslog, CSV, or JSON)
   - Configure log source paths
   - Adjust SIEM forwarding thresholds
   - Set retention period for storage calculations

2. Place your configuration files:
   - Put Panorama running-config.xml files in `config/panorama/`
   - Put individual firewall configs in `config/firewalls/`
   - Place training logs in `data/logs/training/`
   - Place production logs in `data/logs/production/`

3. Run the analyzer:
```bash
python main.py
```

Optionally, you can specify a different config directory:
```bash
python main.py --config-dir /path/to/config
```

## Configuration

The `config.py` file contains several sections:

### Log Sources
```python
LOG_SOURCES = {
    "type": "panorama",  # or "firewall"
    "input_format": "csv",  # or "syslog", "json"
    "input_path": "logs/panorama/"
}
```

### SIEM Settings
```python
SIEM_SETTINGS = {
    "confidence_threshold": 0.8,  # Minimum AI confidence score
    "priority_levels": ["critical", "high"]  # Auto-forward these priorities
}
```

### Storage Settings
```python
STORAGE_SETTINGS = {
    "retention_period_days": 365,
    "compression_ratio": 0.3,
    "storage_buffer": 1.2  # 20% buffer for calculations
}
```

## Output

The analyzer provides:
- SIEM forwarding decisions for each log batch
- EPS calculations (total and forwarded)
- Storage requirement estimates based on retention period
- Filtering efficiency metrics
