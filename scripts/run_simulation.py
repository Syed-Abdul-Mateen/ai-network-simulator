#!/usr/bin/env python3
"""Run an advanced full attack simulation, ML analysis, and reporting."""
import os
import sys
import yaml
import logging
import pickle

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logger import setup_logging
from utils.helpers import ensure_dir
from attack_engine import Scanner, Enumerator, CredentialAttacker, PrivilegeEscalator, LateralMover, MitreMapper
from ai_analysis import LogParser, FeatureExtractor, RootCauseAnalyzer, AttackPathBuilder
from response import Recommendations
from visualization import AttackGraph, ReportGenerator

# Import the model training script
from scripts.train_model import train_and_save_model

def setup_environment(config):
    """Ensure all required directories and files exist."""
    # Create directories for logs, graphs, reports, and models
    ensure_dir(os.path.dirname(config['logging']['file']))
    ensure_dir(os.path.dirname(config['visualization']['graph_output']))
    ensure_dir(os.path.dirname(config['visualization']['report_output']))
    ensure_dir(os.path.dirname(config['ai_analysis']['model_path']))
    ensure_dir(os.path.dirname(config['database']['path']))
    
    # Create empty database file if it doesn't exist
    db_path = config['database']['path']
    if not os.path.exists(db_path):
        open(db_path, 'a').close()

def check_and_train_model(model_path):
    """Train the model if it's missing or is a dummy model."""
    needs_training = False
    if not os.path.exists(model_path):
        needs_training = True
    else:
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            if isinstance(model, dict) and model.get('type') == 'dummy':
                needs_training = True
        except Exception:
            needs_training = True
            
    if needs_training:
        logging.getLogger(__name__).info("No real ML model found. Training advanced model now...")
        train_and_save_model(model_path)

def emit_custom_log(logger, level, src, dest, message):
    """Emit a log that log_parser.py can correctly parse."""
    # log_parser expects: 2023-08-01 12:34:56 [INFO] 192.168.1.10 -> 192.168.1.20: SSH login failed
    # The name field in logger corresponds to the src -> dest part
    if dest:
        name = f"{src} -> {dest}"
    else:
        name = src
    custom_logger = logging.getLogger(name)
    if level == "INFO":
        custom_logger.info(message)
    elif level == "WARNING":
        custom_logger.warning(message)
    elif level == "ERROR":
        custom_logger.error(message)
    else:
        custom_logger.debug(message)

def main():
    # Load config
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Setup environment & logging
    setup_environment(config)
    setup_logging(config['logging'])
    logger = logging.getLogger(__name__)
    
    # Ensure real ML model exists
    check_and_train_model(config['ai_analysis']['model_path'])
    
    # Step 1: Attack simulation with proper parser-friendly logging
    logger.info("Starting advanced attack simulation...")
    
    # Simulate realistic network traffic logs
    emit_custom_log(logger, "INFO", "192.168.1.5", "192.168.1.10", "Network scan initiated (event 0)")
    emit_custom_log(logger, "WARNING", "192.168.1.5", "192.168.1.10", "Port 22 open on target (event 0)")
    
    scanner = Scanner(targets=['192.168.1.10', '192.168.1.20'])
    open_ports = scanner.scan()
    
    enumerator = Enumerator(open_ports)
    enumerated = enumerator.enumerate()
    
    emit_custom_log(logger, "ERROR", "192.168.1.5", "192.168.1.10", "SSH login failed - potential credential brute force (event 1)")
    emit_custom_log(logger, "ERROR", "192.168.1.5", "192.168.1.10", "SSH login failed - invalid user (event 1)")
    emit_custom_log(logger, "WARNING", "192.168.1.5", "192.168.1.10", "SSH login successful for user admin (event 1)")
    
    attacker = CredentialAttacker(enumerated)
    creds = attacker.attack()
    
    emit_custom_log(logger, "ERROR", "192.168.1.10", "192.168.1.10", "Execution error - privilege escalation attempted (event 2)")
    
    escalator = PrivilegeEscalator(creds)
    escalated = escalator.escalate()
    
    emit_custom_log(logger, "WARNING", "192.168.1.10", "192.168.1.20", "Connection established - lateral movement (event 3)")
    
    # Network map
    network_map = {
        '192.168.1.10': ['192.168.1.20'],
        '192.168.1.20': ['192.168.1.10']
    }
    mover = LateralMover(creds, network_map)
    movements = mover.move()
    
    # Step 2: Log analysis
    logger.info("Analyzing logs with ML...")
    parser = LogParser(config['logging']['file'])
    events = parser.parse()
    
    # Enrich events with event_type mimicking extraction logic for the ML model
    for e in events:
        msg = e.get("message", "").lower()
        if "scan" in msg or "port" in msg:
            e["event_type"] = "scan" # 0
        elif "login" in msg or "credential" in msg:
            e["event_type"] = "auth" # 1
        elif "execution" in msg or "privilege" in msg:
            e["event_type"] = "execute" # 2
        else:
            e["event_type"] = "connect" # 3
            
    extractor = FeatureExtractor(config['ai_analysis']['feature_columns'])
    features = extractor.extract(events)
    
    analyzer = RootCauseAnalyzer(config['ai_analysis']['model_path'])
    root_causes = analyzer.analyze(features)
    
    # Step 3: Build attack path
    builder = AttackPathBuilder()
    graph = builder.build(events)
    
    # Step 4: Generate recommendations
    recommender = Recommendations()
    recs = recommender.generate(root_causes)
    
    # Step 5: MITRE mapping
    mapper = MitreMapper(config['attack_engine']['mitre_url'])
    for step in movements:
        tid = mapper.map_step("Lateral Movement")
        logger.info(f"MITRE ID for lateral movement: {tid}")
    
    # Step 6: Visualization
    graph_output = config['visualization']['graph_output']
    viz = AttackGraph()
    viz.plot(graph, graph_output)
    
    # Collect MITRE mappings
    mitre_map = {}
    for step in movements:
        tid = mapper.map_step("Lateral Movement")
        mitre_map[step] = tid
    
    report_gen = ReportGenerator()
    report_gen.generate(
        root_causes, recs, config['visualization']['report_output'],
        events=events,
        graph_image_path=graph_output,
        mitre_mappings=mitre_map,
        movements=movements
    )
    
    logger.info("Simulation completed. Check data/graphs/ and data/reports/ for output.")
    print("\n" + "="*60)
    print("ROOT CAUSES:")
    for cause in root_causes:
        print(f" - {cause.get('cause')} (confidence: {cause.get('confidence', 0.0):.2f})")
    print("\nRECOMMENDATIONS:")
    for r in recs:
        print(f" - {r}")
    print("="*60)

if __name__ == '__main__':
    main()