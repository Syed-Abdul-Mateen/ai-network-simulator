#!/bin/bash
# Setup script for the lab environment
echo "Setting up the lab..."

# Create directories
mkdir -p data/graphs data/logs data/reports

# Create empty database file
touch data/events.db

# Set permissions
chmod +x response/remediation_scripts/fix_misconfig.sh

# Install Python dependencies (if needed)
pip install -r requirements.txt

# Generate dummy model (if not exists)
if [ ! -f ai_analysis/models/rca_model.pkl ]; then
    python -c "import pickle; pickle.dump('dummy_model', open('ai_analysis/models/rca_model.pkl', 'wb'))"
fi

echo "Setup complete. Run 'python scripts/run_simulation.py' to start."