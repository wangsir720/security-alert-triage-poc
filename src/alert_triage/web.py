from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    output_dir = Path("outputs")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            path = self.output_dir / "latest.html"
        elif self.path == "/latest.json":
            path = self.output_dir / "latest.json"
        else:
            self.send_error(404)
            return

        if not path.exists():
            self.send_error(404, "Run the triage pipeline first")
            return

        content_types = {
            ".html": "text/html; charset=utf-8",
            ".json": "application/json; charset=utf-8",
        }
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(path.suffix, "application/octet-stream"))
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the alert triage dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()
    Handler.output_dir = Path(args.output_dir)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Dashboard: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

