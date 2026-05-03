"""Generate security recommendations based on root causes."""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class Recommendations:
    """Provide detailed, actionable remediation actions based on ML root causes."""
    
    def __init__(self):
        self.remediation_map = {
            "Credential brute force": [
                "Enforce multi-factor authentication (MFA) on all remote access points.",
                "Implement account lockout policies after 5 failed attempts.",
                "Deploy a credential stuffing detection system."
            ],
            "Privilege escalation": [
                "Apply the principle of least privilege across all user accounts.",
                "Patch known CVEs on all hosts immediately (CVE-2024-XXXX).",
                "Enable kernel-level exploit protection (KASLR, DEP)."
            ],
            "Lateral movement": [
                "Segment the network into isolated security zones (VLANs).",
                "Restrict administrative access to jump servers only.",
                "Deploy network-level micro-segmentation policies."
            ],
            "Scanning / Reconnaissance": [
                "Enable IDS/IPS signatures for common scan patterns (Nmap, Masscan).",
                "Rate-limit incoming connections per source IP.",
                "Deploy honeypots to detect early reconnaissance activity."
            ],
            "Normal Activity": [
                "Continue baseline monitoring — no immediate action required."
            ]
        }
        self.default_recs = [
            "Review and correlate security logs across all endpoints.",
            "Update firewall rules and intrusion detection signatures.",
            "Conduct a threat hunting exercise to identify hidden indicators of compromise."
        ]
    
    def generate(self, root_causes: List[Dict[str, Any]]) -> List[str]:
        """Return a list of actionable recommendations based on identified root causes."""
        recs = []
        seen = set()
        for cause in root_causes:
            cause_name = cause.get('cause', '')
            # Try exact match first, then partial match
            matched = False
            for key, actions in self.remediation_map.items():
                if key.lower() in cause_name.lower():
                    for action in actions:
                        if action not in seen:
                            recs.append(action)
                            seen.add(action)
                    matched = True
                    break
            if not matched:
                for action in self.default_recs:
                    if action not in seen:
                        recs.append(action)
                        seen.add(action)
        return recs