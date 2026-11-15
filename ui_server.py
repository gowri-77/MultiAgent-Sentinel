from __future__ import annotations

import json
import subprocess
import sys
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
UI_DIR = ROOT / "ui"
EXECUTOR = ThreadPoolExecutor(max_workers=1)
JOBS: dict[str, dict[str, Future]] = {}
JOBS_LOCK = threading.Lock()


def run_project_command(cmd_name: str) -> dict:
    if cmd_name == "demo":
        command = [sys.executable, "demo.py"]
    elif cmd_name == "evaluate":
        command = [sys.executable, "-m", "collusion_guard.evaluate"]
    else:
        return {"success": False, "error": f"Unknown command: {cmd_name}"}

    try:
        proc = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {"success": False, "error": f"Command timed out after 15 minutes.\n{output}"}
    except OSError as exc:
        return {"success": False, "error": f"Could not start command: {exc}"}

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return {
            "success": False,
            "error": output or f"Command exited with code {proc.returncode}.",
            "returncode": proc.returncode,
        }
    return {"success": True, "output": output, "returncode": proc.returncode}


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/results":
            results_path = ROOT / "results.json"
            if not results_path.exists():
                self._send_json({"error": "results.json not found. Run evaluation first."}, 404)
                return
            try:
                with results_path.open("r", encoding="utf-8") as fh:
                    payload = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                self._send_json({"error": f"Could not read results.json: {exc}"}, 500)
                return
            self._send_json(payload)
            return

        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.removeprefix("/api/jobs/")
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if job is None:
                self._send_json({"error": "Job not found."}, 404)
                return
            future = job["future"]
            if not future.done():
                self._send_json({"job_id": job_id, "done": False})
                return
            result = future.result()
            self._send_json({"job_id": job_id, "done": True, **result})
            return

        if parsed.path == "/api/overview":
            self._send_json({
                "project": "Multiagent Sentinel",
                "description": "Risk-aware detection and counterfactual explanation for emergent collusion in multi-agent systems.",
                "status": "ready",
            })
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/run":
            self._send_json({"success": False, "error": "Unsupported endpoint."}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"success": False, "error": "Invalid Content-Length."}, 400)
            return
        if length < 0 or length > 4096:
            self._send_json({"success": False, "error": "Request body is too large."}, 413)
            return

        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"success": False, "error": "Invalid JSON body."}, 400)
            return
        if not isinstance(data, dict) or data.get("command") not in {"demo", "evaluate"}:
            self._send_json({"success": False, "error": "Command must be 'demo' or 'evaluate'."}, 400)
            return

        with JOBS_LOCK:
            if any(not entry["future"].done() for entry in JOBS.values()):
                self._send_json({"success": False, "error": "A project command is already running."}, 409)
                return
            job_id = uuid.uuid4().hex
            future = EXECUTOR.submit(run_project_command, data["command"])
            JOBS[job_id] = {"future": future}
            for old_id in list(JOBS):
                if len(JOBS) <= 20:
                    break
                if JOBS[old_id]["future"].done():
                    del JOBS[old_id]

        self._send_json({"job_id": job_id, "done": False}, 202)


def main():
    host = "127.0.0.1"
    port = 8000
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Serving Multiagent Sentinel UI at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Multiagent Sentinel dashboard.")
    finally:
        server.server_close()
        EXECUTOR.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
