"""Logging configuration."""
import logging
import logging.config
import os

def setup_logging(config):
    """Set up logging based on config dict."""
    log_level = getattr(logging, config.get('level', 'INFO').upper())
    log_file = config.get('file', 'simulation.log')
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ],
        force=True
    )