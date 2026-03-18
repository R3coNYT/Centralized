"""
Launch AutoRecon from the Centralized web interface.
Output is streamed in real-time via Server-Sent Events (SSE) — no WebSocket needed,
works with any WSGI server (waitress, gunicorn, dev server).
"""
import os
import re
import sys
import uuid
import queue
import threading
import subprocess

from flask import (
    Blueprint, Response, abort, jsonify, render_template,
    request, stream_with_context,
)
from flask_login import login_required

autorecon_launch_bp = Blueprint("autorecon_launch", __name__, url_prefix="/autorecon")

AUTORECON_DIR     = r"C:\Tools\AutoRecon"
AUTORECON_MAIN    = os.path.join(AUTORECON_DIR, "main.py")
AUTORECON_VENV_PY = os.path.join(AUTORECON_DIR, "venv", "Scripts", "python.exe")

# ── Session registry ──────────────────────────────────────────────────────────
# {session_id: {"proc": Popen, "queue": Queue}}
_sessions: dict = {}
_lock = threading.Lock()

# Accepts FQDN, bare hostname, IPv4, IPv4/CIDR — rejects any shell metacharacters
_TARGET_RE = re.compile(
    r'^(?:'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'  # FQDN
    r'|(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?)'                      # bare hostname
    r'|(?:\d{1,3}\.){3}\d{1,3}(?:/(?:[12]?\d|3[0-2]))?'                      # IPv4 / CIDR
    r')$'
)


def _reader(proc: subprocess.Popen, q: queue.Queue) -> None:
    """Background thread: read stdout/stderr lines and push to queue."""
    try:
        for raw in iter(proc.stdout.readline, b""):
            q.put(raw.decode("utf-8", errors="replace"))
    finally:
        q.put(None)  # sentinel — tells the SSE generator to close


def _python_exe() -> str:
    return AUTORECON_VENV_PY if os.path.isfile(AUTORECON_VENV_PY) else sys.executable


# ── Routes ────────────────────────────────────────────────────────────────────

@autorecon_launch_bp.route("/")
@login_required
def launch_page():
    return render_template("autorecon/launch.html")


@autorecon_launch_bp.route("/start", methods=["POST"])
@login_required
def start_scan():
    data   = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()

    if not target or not _TARGET_RE.match(target):
        return jsonify({"error": "Invalid target (domain, IP or CIDR required)."}), 400

    # Build CLI args from validated, pre-defined options only (prevents injection)
    args = ["-t", target]

    if data.get("full"):
        args.append("--full")
    if data.get("no_crawl"):
        args.append("--no-crawl")
    if data.get("no_nvd"):
        args.append("--no-nvd")
    if data.get("pdf"):
        args.append("--pdf")

    threads_val = data.get("threads")
    if isinstance(threads_val, int) and 1 <= threads_val <= 64:
        args += ["--threads", str(threads_val)]

    cmd = [_python_exe(), AUTORECON_MAIN] + args

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            cwd=AUTORECON_DIR,
            bufsize=0,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    sid = str(uuid.uuid4())
    q   = queue.Queue()
    t   = threading.Thread(target=_reader, args=(proc, q), daemon=True)
    t.start()

    with _lock:
        _sessions[sid] = {"proc": proc, "queue": q}

    return jsonify({"session_id": sid})


@autorecon_launch_bp.route("/stream/<session_id>")
@login_required
def stream(session_id: str):
    with _lock:
        session = _sessions.get(session_id)
    if not session:
        abort(404)

    def generate():
        q = session["queue"]
        while True:
            try:
                line = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue

            if line is None:
                # Process finished — send end sentinel then clean up
                yield "data: \x00\n\n"
                with _lock:
                    _sessions.pop(session_id, None)
                break

            # Strip trailing newline so SSE framing stays valid
            yield f"data: {line.rstrip(chr(10))}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@autorecon_launch_bp.route("/input/<session_id>", methods=["POST"])
@login_required
def send_input(session_id: str):
    with _lock:
        session = _sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    text = (request.get_json(silent=True) or {}).get("input", "")
    try:
        session["proc"].stdin.write((text + "\n").encode())
        session["proc"].stdin.flush()
    except OSError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"ok": True})


@autorecon_launch_bp.route("/kill/<session_id>", methods=["POST"])
@login_required
def kill_scan(session_id: str):
    with _lock:
        session = _sessions.pop(session_id, None)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    proc = session["proc"]
    try:
        if os.name == "nt":
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            import signal as _signal
            os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    return jsonify({"ok": True})
