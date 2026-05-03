"""Map attack steps to MITRE ATT&CK techniques."""
import json
import requests
import logging
logger = logging.getLogger(__name__)

class MitreMapper:
    """Map attack steps to MITRE ATT&CK IDs."""
    
    def __init__(self, mitre_url: str):
        self.mitre_url = mitre_url
        self.techniques = self._load_techniques()
    
    def _load_techniques(self):
        """Fetch MITRE ATT&CK data (or load from a local file)."""
        try:
            response = requests.get(self.mitre_url)
            data = response.json()
            # Simplified: return a dict mapping technique name to ID
            techniques = {}
            for obj in data.get('objects', []):
                if obj['type'] == 'attack-pattern':
                    techniques[obj['name']] = obj['external_references'][0]['external_id']
            return techniques
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            # Fallback mapping
            return {
                "Brute Force": "T1110",
                "Privilege Escalation": "T1068",
                "Lateral Movement": "T1021"
            }
    
    def map_step(self, step_name: str) -> str:
        """Return MITRE ID for a step if found, else 'Unknown'."""
        for name, tid in self.techniques.items():
            if step_name.lower() in name.lower():
                return tid
        return "Unknown"