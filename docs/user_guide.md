# User Guide

## Getting Started
1. Run `python scripts/run_simulation.py` to execute a full attack simulation.
2. Check the logs in `data/logs/simulation.log`.
3. View the generated attack graph at `data/graphs/attack_path.png`.
4. Read the final report at `data/reports/final_report.pdf`.
5. Start the web dashboard with `python scripts/start_dashboard.py` and open `http://localhost:5000`.

## Configuration
Edit `config.yaml` to change:
- Logging level and file location.
- Database path.
- Attack engine parameters.
- Model paths.

## Customization
- Add your own attack techniques by extending `attack_engine` classes.
- Train a new model by modifying `ai_analysis/feature_extractor.py` and `root_cause_analyzer.py`.
- Customize the web dashboard in `web_dashboard/`.