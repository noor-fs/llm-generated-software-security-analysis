"""Run the local comparison server without exposing Werkzeug/Python versions."""
import argparse
from werkzeug.serving import WSGIRequestHandler, run_simple
from app import app


class DemoBankRequestHandler(WSGIRequestHandler):
    @property
    def server_version(self):
        return "DemoBank"

    def version_string(self):
        return "DemoBank"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run DemoBank V2 locally")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5002)
    args = parser.parse_args()
    run_simple(args.host, args.port, app, request_handler=DemoBankRequestHandler,
               use_reloader=False, use_debugger=False, threaded=True)
