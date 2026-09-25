from pyvis.network import Network
import tempfile
import os

def generate_crypto_graph(findings):
    """
    Generates a PyVis interactive network graph representing the Cryptographic
    Topology of the scanned enterprise application.
    Nodes: Files, Algorithms
    Edges: "Uses"
    """
    net = Network(height="600px", width="100%", bgcolor="#0e1117", font_color="white", directed=True)
    
    # Track added nodes to avoid duplicates
    added_nodes = set()
    
    # Base Application Node
    net.add_node("App", label="Enterprise App", color="#00ff00", shape="star", size=30)
    added_nodes.add("App")
    
    for f in findings:
        file_node = f['file'].split('/')[-1]
        algo_node = f['name']
        risk_tier = f['risk']['tier']
        
        # Color nodes based on risk
        algo_color = "#ff4b4b" if risk_tier == "CRITICAL" else ("#ff9f36" if risk_tier == "HIGH" else "#00b4d8")
        
        # Add File Node
        if file_node not in added_nodes:
            net.add_node(file_node, label=file_node, color="#ffffff", shape="box")
            added_nodes.add(file_node)
            net.add_edge("App", file_node)
            
        # Add Algorithm Node
        algo_id = f"{file_node}_{algo_node}"
        if algo_id not in added_nodes:
            # We use a unique ID so we can have multiple of the same algo in different files
            net.add_node(algo_id, label=algo_node, color=algo_color, shape="dot", size=20, 
                         title=f"Risk: {risk_tier}\nScore: {f['risk']['x_y']}")
            added_nodes.add(algo_id)
            
            # Connect File to Algorithm
            net.add_edge(file_node, algo_id)
            
    # Configure physics for a nice bouncy graph layout
    net.force_atlas_2based()
    
    # Save to a temporary HTML file and read it back
    fd, tmp_path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    
    # Pyvis save_graph needs a path string
    net.save_graph(tmp_path)
    
    with open(tmp_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
        
    os.unlink(tmp_path)
    return html_content
