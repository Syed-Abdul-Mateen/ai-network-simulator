#!/usr/bin/env python3
"""Train the Machine Learning model for Root Cause Analysis."""
import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import logging

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.helpers import load_config, ensure_dir

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

def generate_synthetic_data(num_samples=1000):
    """Generate synthetic feature data for training the model.
    Features expected by extractor: hour, day, event_type_enc, status_enc
    """
    logger.info(f"Generating {num_samples} synthetic training samples...")
    np.random.seed(42)
    
    # Generate random features
    hours = np.random.randint(0, 24, num_samples)
    days = np.random.randint(0, 7, num_samples)
    
    # Event types: 0: scan, 1: auth, 2: execute, 3: connect
    event_types = np.random.randint(0, 4, num_samples)
    
    # Status: 0: info, 1: warning, 2: error, 3: critical
    statuses = np.random.randint(0, 4, num_samples)
    
    X = pd.DataFrame({
        'hour': hours,
        'day': days,
        'event_type_enc': event_types,
        'status_enc': statuses
    })
    
    # Generate target labels based on some rules to make the model learnable
    y = []
    for i in range(num_samples):
        # Credential brute force: high auth failures (event 1, status 2) at weird hours
        if event_types[i] == 1 and statuses[i] >= 2 and (hours[i] < 6 or hours[i] > 22):
            y.append("Credential brute force")
        # Privilege escalation: execution errors (event 2, status 3)
        elif event_types[i] == 2 and statuses[i] == 3:
            y.append("Privilege escalation")
        # Lateral movement: connect events (event 3, status 1 or 2)
        elif event_types[i] == 3 and statuses[i] >= 1:
            y.append("Lateral movement")
        # Recon/Scanning: scan events (event 0)
        elif event_types[i] == 0 and statuses[i] >= 1:
            y.append("Scanning / Reconnaissance")
        else:
            y.append("Normal Activity")
            
    return X, np.array(y)

def train_and_save_model(model_path):
    """Train the RF classifier and save to pickle."""
    ensure_dir(os.path.dirname(model_path))
    
    X, y = generate_synthetic_data(2000)
    
    logger.info("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    accuracy = clf.score(X, y)
    logger.info(f"Model trained with training accuracy: {accuracy:.2f}")
    
    # Save the model
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
        
    logger.info(f"Model saved successfully to {model_path}")

if __name__ == '__main__':
    config = load_config()
    model_path = config['ai_analysis']['model_path']
    train_and_save_model(model_path)
