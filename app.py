"""IndraMesh Web Console Launcher.

Replaces the legacy Streamlit front end with a modern, high-performance,
cybersecurity HUD console powered by FastAPI, Uvicorn, and HTML5/Canvas.

Usage:
    python app.py                 # Runs the console on http://127.0.0.1:8501
    python app.py --port 8000     # Runs on custom port
"""
import argparse
import os
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from server import app as fastapi_app

# Graceful bridge if invoked via `streamlit run app.py`
try:
    import streamlit as st
    if hasattr(st, "runtime") and st.runtime.exists():
        st.set_page_config(page_title="IndraMesh Console", layout="wide", page_icon="🛡️")
        st.title("🛡️ INDRAMESH (इन्द्रमेश)")
        st.subheader("Enterprise Cryptographic Discovery, Inventory (ACDI) & Post-Quantum Migration Mesh")
        st.info("🚀 **IndraMesh has migrated to a High-Performance FastAPI Cyber HUD Console.**")
        st.markdown(
            """
            To launch the full interactive Cyber HUD console, CycloneDX v1.7 CBOM generator,
            and real-time telemetry array, run:
            
            ```bash
            python app.py
            ```
            Then access the HUD at **http://127.0.0.1:8501**
            """
        )
except Exception:
    pass



def run_server(host: str = "0.0.0.0", port: int = 8501, reload: bool = False):
    """Start the Uvicorn web server."""
    import uvicorn

    print("=" * 78)
    print("IndraMesh -- Enterprise Cryptographic Discovery & Analysis Tool")
    print(f"  Live Console:  http://127.0.0.1:{port}")
    print(f"  Localhost:     http://localhost:{port}")
    print(f"  API Docs:      http://127.0.0.1:{port}/docs")
    print("  Engine:        FastAPI + IndraMesh Core (Zero Streamlit requirement)")
    print("=" * 78)

    uvicorn.run("server:app", host=host, port=port, log_level="info", reload=reload)


def main():
    parser = argparse.ArgumentParser(description="Launch the IndraMesh Web Console")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8501, help="Port number (default: 8501)")
    parser.add_argument("--reload", action="store_true", help="Enable live auto-reload for development")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
