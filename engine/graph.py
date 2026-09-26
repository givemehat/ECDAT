"""Interactive topology graph (PyVis).

Nodes: the scanned application, each file, and each cryptographic artefact.
Edges: file -> artefact (`uses`). A library finding is presence evidence, so it is rendered
differently from a primitive that code actually calls.
"""
import os
import tempfile

from pyvis.network import Network

COLORS = {"CRITICAL": "#ff4b4b", "HIGH": "#ff9f36", "MEDIUM": "#ffd166", "LOW": "#4cc9f0"}


def generate_crypto_graph(findings):
    net = Network(height="620px", width="100%", bgcolor="#0e1117", font_color="white", directed=True)
    added = set()
    net.add_node("App", label="Scanned application", color="#00ff9f", shape="star", size=30)
    added.add("App")

    for f in findings:
        file_node = os.path.basename(str(f.get("file", "unknown")))
        risk = (f.get("risk") or {}).get("tier", "LOW")
        is_library = f.get("type") == "library"
        label = f"{f['name']}" + (f" ({f['key_length']})" if f.get("key_length") else "")
        title = (f"Tier: {risk}\n"
                 f"Primitive: {f.get('primitive', '-')}\n"
                 f"Rule: {f.get('rule_id', '-')}\n"
                 f"Evidence: {f.get('evidence_class', '-')}")
        if is_library:
            title = f"LIBRARY (implements, not uses)\n" + title

        if file_node not in added:
            net.add_node(file_node, label=file_node, color="#ffffff", shape="box")
            added.add(file_node)
            net.add_edge("App", file_node)

        node_id = f"{file_node}__{f['name']}"
        if node_id in added:
            continue
        net.add_node(node_id, label=label, title=title,
                     color="#8d99ae" if is_library else COLORS.get(risk, "#4cc9f0"),
                     shape="dot" if is_library else "diamond", size=22)
        added.add(node_id)
        net.add_edge(file_node, node_id, dashes=is_library)

    net.force_atlas_2based()

    fd, tmp_path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    try:
        net.save_graph(tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
