# PanLogs Analyzer

An AI-powered log analysis tool for Palo Alto firewalls and Panorama log collectors. This tool helps determine which logs should be forwarded to SIEM systems and provides storage sizing calculations based on retention requirements.

## Features

- AI-based log analysis for SIEM forwarding decisions
- Storage size calculation based on retention period
- Events per second (EPS) calculation
- Support for Palo Alto firewall and Panorama log formats

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

## Usage

1. Configure your log sources in `config.py`
2. Run the analyzer:
```bash
python main.py
```

## Configuration

Edit `config.py` to set:
- Log input sources
- AI model parameters
- SIEM forwarding rules
- Retention period
