<div align="center">

# Cyber Attack Path Analyzer

**AI-Powered Network Threat Simulation and Root Cause Analysis Framework**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML%20Pipeline-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

A comprehensive cybersecurity simulation framework that models multi-stage attack lifecycles, applies machine learning for automated root cause analysis, maps techniques to the MITRE ATT&CK framework, and presents findings through a real-time dark-themed web dashboard.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Technologies](#technologies)

---

## Overview

The Cyber Attack Path Analyzer simulates a realistic network intrusion scenario end-to-end:

1. **Reconnaissance and Scanning** - TCP port scanning across target hosts
2. **Service Enumeration** - Identifying running services on discovered ports
3. **Credential Attacks** - Brute-force authentication attempts
4. **Privilege Escalation** - Exploiting elevated access
5. **Lateral Movement** - Propagating across the network using compromised credentials

After the attack simulation completes, the system parses the generated logs, extracts features, and feeds them into a trained **Random Forest Classifier** to identify the root causes of security events. It then generates actionable remediation recommendations, produces an attack path graph (PNG), and compiles a PDF report.

---

## Architecture

```
                    +-------------------+
                    |   config.yaml     |
                    +--------+----------+
                             |
              +--------------+--------------+
              |                             |
   +----------v----------+     +-----------v-----------+
   |   Attack Engine      |     |   AI Analysis          |
   |                      |     |                        |
   |  Scanner             |     |  LogParser             |
   |  Enumerator          |     |  FeatureExtractor      |
   |  CredentialAttacker   |     |  RootCauseAnalyzer     |
   |  PrivilegeEscalator   |     |  AttackPathBuilder     |
   |  LateralMover        |     |                        |
   |  MitreMapper         |     |  RandomForestClassifier |
   +----------+-----------+     +-----------+------------+
              |                             |
              +-------------+---------------+
                            |
              +-------------v--------------+
              |     Response Engine         |
              |  Recommendations           |
              +-------------+--------------+
                            |
              +-------------v--------------+
              |     Visualization           |
              |  AttackGraph (PNG)          |
              |  ReportGenerator (PDF)     |
              +-------------+--------------+
                            |
              +-------------v--------------+
              |     Web Dashboard (Flask)   |
              |  Real-time event log       |
              |  Interactive attack graph  |
              |  Root cause analysis bars  |
              |  Remediation actions       |
              +----------------------------+
```

---

## Features

### Attack Simulation Engine
- TCP connect scanning with configurable port lists and timeouts
- Service enumeration with banner grabbing
- Dictionary-based credential attack simulation
- Privilege escalation modeling
- Lateral movement across a defined network topology
- MITRE ATT&CK technique mapping with live data fetching and offline fallback

### Machine Learning Pipeline
- Automated model training using a `RandomForestClassifier` (scikit-learn)
- Feature extraction from structured log data (temporal, categorical, and status-based features)
- Root cause classification across five categories:
  - Credential Brute Force
  - Privilege Escalation
  - Lateral Movement
  - Scanning / Reconnaissance
  - Normal Activity
- Confidence-scored predictions using `predict_proba()`

### Visualization and Reporting
- Directed attack path graph rendered with NetworkX and Matplotlib
- PDF report generation with root causes and remediation actions (ReportLab)
- Canvas-based interactive attack topology in the web dashboard

### Real-Time Web Dashboard
- Dark-themed glassmorphism UI built with Flask, HTML5, and vanilla CSS
- Stats overview: total events, threats detected, ML model status, last scan time
- Live security event log table with severity badges
- Interactive attack path topology rendered on HTML Canvas
- Root cause analysis breakdown with horizontal progress bars
- Actionable remediation recommendations panel
- One-click simulation trigger from the dashboard
- Auto-refresh every 30 seconds

---

## Project Structure

```
ai_network_simulator/
|
|-- attack_engine/              # Attack simulation modules
|   |-- __init__.py
|   |-- scanner.py              # TCP port scanner
|   |-- enumeration.py          # Service enumeration
|   |-- credential_attacks.py   # Brute-force credential attacks
|   |-- privilege_escalation.py # Privilege escalation simulation
|   |-- lateral_movement.py     # Network lateral movement
|   |-- mitre_mapper.py         # MITRE ATT&CK technique mapping
|
|-- ai_analysis/                # Machine learning analysis
|   |-- __init__.py
|   |-- log_parser.py           # Structured log parser
|   |-- feature_extractor.py    # Feature engineering from events
|   |-- root_cause_analyzer.py  # ML-based root cause prediction
|   |-- attack_path_builder.py  # Directed graph construction
|   |-- models/                 # Trained model storage (auto-generated)
|
|-- response/                   # Automated response engine
|   |-- __init__.py
|   |-- recommendations.py      # Remediation action generator
|   |-- remediation_scripts/    # Automated fix scripts
|
|-- visualization/              # Output generation
|   |-- __init__.py
|   |-- attack_graph.py         # Attack path PNG renderer
|   |-- report_generator.py     # PDF report builder
|
|-- web_dashboard/              # Flask web application
|   |-- app.py                  # Flask routes and API endpoints
|   |-- templates/
|   |   |-- index.html          # Dashboard frontend
|   |-- static/
|       |-- style.css           # Dark-themed glassmorphism stylesheet
|
|-- scripts/                    # Entry-point scripts
|   |-- run_simulation.py       # Full simulation pipeline
|   |-- start_dashboard.py      # Dashboard launcher
|   |-- train_model.py          # Standalone ML model trainer
|
|-- utils/                      # Shared utilities
|   |-- helpers.py              # Config loader, directory helpers
|   |-- logger.py               # Logging configuration
|
|-- tests/                      # Unit tests
|   |-- test_attack_engine.py
|   |-- test_ai_analysis.py
|
|-- data/                       # Generated output (gitignored)
|   |-- graphs/                 # Attack path PNGs
|   |-- logs/                   # Simulation logs
|   |-- reports/                # PDF reports
|
|-- config.yaml                 # Central configuration
|-- requirements.txt            # Python dependencies
|-- .gitignore
|-- README.md
```

---

## Prerequisites

- **Python 3.10** or higher
- **pip** package manager
- **Git** (for cloning the repository)

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/Syed-Abdul-Mateen/ai-network-simulator.git
cd ai-network-simulator
```

**2. Create and activate a virtual environment**

```bash
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

No additional setup is required. All data directories and ML model files are created automatically on first run.

---

## Usage

### Run the Full Simulation

This command executes the complete pipeline: environment setup, ML model training (if needed), attack simulation, log analysis, root cause prediction, and report generation.

```bash
python scripts/run_simulation.py
```

**Expected output:**

```
============================================================
ROOT CAUSES:
 - Lateral movement (confidence: 1.00)
 - Scanning / Reconnaissance (confidence: 0.99)

RECOMMENDATIONS:
 - Segment the network into isolated security zones (VLANs).
 - Restrict administrative access to jump servers only.
 - Deploy network-level micro-segmentation policies.
 - Enable IDS/IPS signatures for common scan patterns (Nmap, Masscan).
 - Rate-limit incoming connections per source IP.
 - Deploy honeypots to detect early reconnaissance activity.
============================================================
```

### Generated Artifacts

| Output | Location |
|--------|----------|
| Attack path graph | `data/graphs/attack_path.png` |
| PDF report | `data/reports/final_report.pdf` |
| Simulation log | `data/logs/simulation.log` |
| Trained ML model | `ai_analysis/models/rca_model.pkl` |

### Train the ML Model Independently

```bash
python scripts/train_model.py
```

---

## Web Dashboard

Start the real-time monitoring dashboard:

```bash
python scripts/start_dashboard.py
```

Open your browser and navigate to:

```
http://localhost:5000
```

### Dashboard Sections

| Section | Description |
|---------|-------------|
| **Stats Row** | Total events, threats detected, ML model status, last scan time |
| **Security Event Log** | Tabular view of parsed log events with severity badges |
| **Attack Path Topology** | Canvas-rendered directed graph of attack paths |
| **Remediation Actions** | Prioritized list of security recommendations |
| **Root Cause Analysis** | Breakdown of event severity distribution |
| **System Overview** | Log file path, model state, system status |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/events` | Returns the last 50 parsed security events |
| `GET` | `/api/graph` | Returns attack graph nodes and edges |
| `GET` | `/api/recommendations` | Returns ML-driven remediation actions |
| `GET` | `/api/status` | Returns system and model status |
| `POST` | `/api/run-simulation` | Triggers a full simulation run |

---

## Configuration

All settings are centralized in `config.yaml`:

```yaml
# Attack engine
attack_engine:
  threads: 4
  timeout: 30
  mitre_url: "https://raw.githubusercontent.com/.../enterprise-attack.json"

# AI analysis
ai_analysis:
  model_path: "ai_analysis/models/rca_model.pkl"
  feature_columns:
    - "timestamp"
    - "source_ip"
    - "dest_ip"
    - "event_type"
    - "status"
    - "message"

# Web dashboard
dashboard:
  host: "0.0.0.0"
  port: 5000
  debug: false
```

---

## Technologies

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Machine Learning | scikit-learn (RandomForestClassifier) |
| Graph Analysis | NetworkX |
| Visualization | Matplotlib |
| PDF Reports | ReportLab |
| Web Framework | Flask |
| Frontend | HTML5, CSS3 (Glassmorphism), JavaScript (Canvas API) |
| Configuration | YAML |
| Threat Intelligence | MITRE ATT&CK Framework |

---

<div align="center">

**Cyber Attack Path Analyzer** -- Built for cybersecurity research and educational simulation.

</div>
