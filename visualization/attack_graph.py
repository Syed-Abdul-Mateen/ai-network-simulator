"""Generate a visual representation of the attack path."""
import networkx as nx
import matplotlib.pyplot as plt
import logging

logger = logging.getLogger(__name__)

class AttackGraph:
    """Plot a directed graph of attack steps."""
    
    def __init__(self):
        pass
    
    def plot(self, graph: nx.DiGraph, output_path: str):
        """Render graph to a PNG file."""
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True, node_color='lightblue', 
                edge_color='gray', arrows=True, font_size=10)
        plt.title("Attack Path Graph")
        plt.savefig(output_path, format='png', dpi=150)
        plt.close()
        logger.info(f"Attack graph saved to {output_path}")