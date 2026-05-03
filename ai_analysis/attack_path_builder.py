"""Build attack path graphs from events."""
import networkx as nx
from typing import List, Dict, Any

class AttackPathBuilder:
    """Construct a directed graph representing attack steps."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
    
    def build(self, events: List[Dict[str, Any]]) -> nx.DiGraph:
        """Add nodes and edges based on event patterns."""
        for event in events:
            src = event.get('source_ip')
            dst = event.get('dest_ip')
            if src and dst:
                self.graph.add_edge(src, dst, event_type=event.get('event_type'), 
                                    message=event.get('message'))
            else:
                # Add a node for the event itself
                node_id = f"{event['timestamp']}_{event['event_type']}"
                self.graph.add_node(node_id, **event)
        return self.graph