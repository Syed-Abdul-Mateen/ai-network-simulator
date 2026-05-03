"""Move laterally across the network."""
import logging
logger = logging.getLogger(__name__)

class LateralMover:
    """Use compromised credentials to access other hosts."""
    
    def __init__(self, compromised_creds: dict, network_map: dict):
        """
        Args:
            compromised_creds: {ip: {'user': str, 'password': str}}
            network_map: {ip: [neighbor_ips]}
        """
        self.creds = compromised_creds
        self.network_map = network_map
    
    def move(self):
        """Attempt to use credentials on other hosts."""
        movements = {}
        for ip, cred in self.creds.items():
            if cred:
                for neighbor in self.network_map.get(ip, []):
                    # Simulate successful movement
                    movements[f"{ip} -> {neighbor}"] = {'user': cred['user'], 'password': cred['password']}
                    logger.info(f"Moved from {ip} to {neighbor}")
        return movements