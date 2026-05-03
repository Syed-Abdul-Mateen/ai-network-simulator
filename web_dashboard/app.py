"""Flask web application for real-time monitoring with dark theme."""
import os
import sys
import json
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.helpers import load_config, ensure_dir
from ai_analysis import LogParser, FeatureExtractor, RootCauseAnalyzer, AttackPathBuilder

app = Flask(__name__)

# Resolve config relative to project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
os.chdir(PROJECT_ROOT)
config = load_config()

# Ensure data directories exist
ensure_dir(os.path.dirname(config['logging']['file']))
ensure_dir(os.path.dirname(config['visualization']['graph_output']))
ensure_dir(os.path.dirname(config['visualization']['report_output']))

def enrich_events(events):
    """Add event_type classification to parsed events for ML pipeline."""
    for e in events:
        msg = e.get("message", "").lower()
        if "scan" in msg or "port" in msg:
            e["event_type"] = "scan"
        elif "login" in msg or "credential" in msg:
            e["event_type"] = "auth"
        elif "execution" in msg or "privilege" in msg:
            e["event_type"] = "execute"
        else:
            e["event_type"] = "connect"
    return events


@app.route('/')
def index():
    """Dashboard homepage."""
    return render_template('index.html')


@app.route('/api/events')
def api_events():
    """Return latest events as JSON."""
    try:
        log_file = config['logging']['file']
        if not os.path.exists(log_file):
            return jsonify([])
        parser = LogParser(log_file)
        events = parser.parse()
        # Convert datetime to string for JSON
        for e in events:
            if 'timestamp' in e and isinstance(e['timestamp'], datetime):
                e['timestamp'] = e['timestamp'].isoformat()
        return jsonify(events[-50:])  # return last 50 events
    except Exception as e:
        app.logger.error(f"Error fetching events: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/graph')
def api_graph():
    """Return attack graph data as JSON."""
    try:
        log_file = config['logging']['file']
        if not os.path.exists(log_file):
            return jsonify({"nodes": [], "edges": []})
        parser = LogParser(log_file)
        events = parser.parse()
        builder = AttackPathBuilder()
        graph = builder.build(events)
        nodes = list(graph.nodes)
        edges = [{"source": u, "target": v, "type": d.get('event_type', ''), "weight": d.get('weight', 1)}
                 for u, v, d in graph.edges(data=True)]
        return jsonify({"nodes": nodes, "edges": edges})
    except Exception as e:
        app.logger.error(f"Error fetching graph: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/recommendations')
def api_recommendations():
    """Return recommendations as JSON."""
    try:
        log_file = config['logging']['file']
        if not os.path.exists(log_file):
            return jsonify(["Run a simulation first to generate recommendations."])
        parser = LogParser(log_file)
        events = parser.parse()
        events = enrich_events(events)
        extractor = FeatureExtractor(config['ai_analysis']['feature_columns'])
        features = extractor.extract(events)
        analyzer = RootCauseAnalyzer(config['ai_analysis']['model_path'])
        causes = analyzer.analyze(features)
        from response.recommendations import Recommendations
        recommender = Recommendations()
        recs = recommender.generate(causes)
        return jsonify(recs)
    except Exception as e:
        app.logger.error(f"Error fetching recommendations: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/status')
def api_status():
    """Return system status."""
    model_path = config['ai_analysis']['model_path']
    model_loaded = os.path.exists(model_path)
    # Check if it's a real model (not dummy)
    if model_loaded:
        try:
            import pickle
            with open(model_path, 'rb') as f:
                m = pickle.load(f)
            if isinstance(m, dict) and m.get('type') == 'dummy':
                model_loaded = False
        except Exception:
            pass

    return jsonify({
        "status": "running",
        "log_file": config['logging']['file'],
        "model_loaded": model_loaded
    })


@app.route('/api/run-simulation', methods=['POST'])
def api_run_simulation():
    """Trigger the simulation script."""
    try:
        result = subprocess.run(
            [sys.executable, os.path.join('scripts', 'run_simulation.py')],
            capture_output=True, text=True, timeout=120,
            cwd=PROJECT_ROOT
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr or "Simulation failed"}), 500
        return jsonify({"status": "ok", "output": result.stdout[-500:]})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Simulation timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host=config['dashboard']['host'], port=config['dashboard']['port'], debug=config['dashboard']['debug'])