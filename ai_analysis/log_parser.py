"""Parse log files into structured events."""
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

class LogParser:
    """Parse simulation logs into event dictionaries."""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.events: List[Dict[str, Any]] = []
        
    def parse(self) -> List[Dict[str, Any]]:
        """Read log file and parse each line."""
        self.events = []  # Reset on each call
        with open(self.log_file, 'r') as f:
            for line in f:
                event = self._parse_line(line.strip())
                if event:
                    self.events.append(event)
        return self.events
    
    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line into an event dict.
        
        Handles both formats:
          Classic:  2023-08-01 12:34:56 [INFO] 192.168.1.10 -> 192.168.1.20: message
          Python:   2026-05-03 14:13:01,950 [INFO] 192.168.1.5 -> 192.168.1.10: message
        """
        # Pattern handles optional millisecond comma suffix in timestamp
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)? \[(\w+)\] (.*?): (.*)'
        match = re.match(pattern, line)
        if not match:
            return None
        
        timestamp_str, level, src_dest, message = match.groups()
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        
        # Extract source and destination if present
        src_ip, dest_ip = None, None
        if ' -> ' in src_dest:
            parts = src_dest.split(' -> ')
            src_ip = parts[0].strip()
            dest_ip = parts[1].strip() if len(parts) > 1 else None
        
        return {
            "timestamp": timestamp,
            "level": level,
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "event_type": "log",
            "status": level,
            "message": message
        }