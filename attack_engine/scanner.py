"""Network and service scanning."""
import socket
import logging

logger = logging.getLogger(__name__)

class Scanner:
    """Scan target IPs for open ports."""
    
    def __init__(self, targets: list):
        self.targets = targets
        self.open_ports = {}
    
    def scan(self, ports: list = [22, 80, 443, 445, 3389]):
        """Perform a simple TCP connect scan."""
        for ip in self.targets:
            self.open_ports[ip] = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        self.open_ports[ip].append(port)
                        logger.info(f"Port {port} open on {ip}")
                    sock.close()
                except Exception as e:
                    logger.error(f"Error scanning {ip}:{port} - {e}")
        return self.open_ports