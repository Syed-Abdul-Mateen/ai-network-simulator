#!/usr/bin/env python3
"""Start the web dashboard."""
import os
import sys
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web_dashboard.app import app

if __name__ == '__main__':
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    dashboard_config = config['dashboard']
    app.run(host=dashboard_config['host'], port=dashboard_config['port'], debug=dashboard_config['debug'])