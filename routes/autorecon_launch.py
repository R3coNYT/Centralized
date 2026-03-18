"""
AutoRecon interactive terminal via SSE.

Launches AutoRecon as a fully interactive process (PTY when available) and
streams its output to the browser in real time.  xterm.js sends raw keystrokes
(including arrow-key escape sequences) back to the process stdin so the
AutoRecon interactive CLI works exactly like a local terminal.

PTY support (strongly recommended for arrow keys / cursor movement):
  Windows  : pip install pywinpty>=2.0
  Linux/mac: pip install ptyprocess>=0.7
Without a PTY the process runs with plain pipes; basic text input still works
but readline/curses-based navigation will be limited.
"""
import base64
import os
import queue
import shutil
import subprocess
import threading
import time
import uuid

from flask import Blueprint, Response, jsonify, render_template, request, stream_with_context
from flask_login import login_required

autorecon_launch_bp = Blueprint("autorecon_launch", __name__, url_prefix="/autorecon")

# ── PTY backend detection ─────────────────────────────────────────────────────

_PTY_TYPE: str | None = None  # "winpty" | "ptyprocess" | None

if os.name == "nt":
    try:
        import winpty as _winpty      # pywinpty 2.x  (pip install pywinpty)
        _PTY_TYPE = "winpty"
    except ImportError:
        pass
else:
    try:
        from ptyprocess import PtyProcessUnicode as _PtyProcess   # pip install ptyprocess
        _PTY_TYPE = "ptyprocess"
    except ImportError:
        pass


def _spawn(cmd: list, rows: int, cols: int):
    """
    Spawn *cmd* inside a PTY (when available) or a plain subprocess.
    Returns the process object; the caller must check _PTY_TYPE to know which
    API to use.
    """
    if _PTY_TYPE == "ptyprocess":
        return _PtyProcess.spawn(cmd, dimensions=(rows, cols))

    if _PTY_TYPE == "winpty":
        # winpty.PtyProcess.spawn expects a single string command.
        # Wrap .bat files through cmd.exe so Windows executes them properly.
        cmdlist = list(cmd)
        if cmdlist[0].lower().endswith(".bat"):
            cmdlist = ["cmd.exe", "/C"] + cmdlist
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmdlist)
        return _winpty.PtyProcess.spawn(cmd_str, dimensions=(rows, cols))

    # Fallback: plain subprocess with pipes
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
    )


# ── AutoRecon command detection ───────────────────────────────────────────────

def find_autorecon():
    """Return the argv list needed to start AutoRecon, or None if not found."""
    # Windows: prefer the .bat launcher
    if os.name == "nt":
        bat = r"C:\Tools\AutoRecon\AutoRecon.bat"
        if os.path.isfile(bat):
            return [bat]

    # Any platform: check PATH
    for name in ("AutoRecon", "autorecon"):
        found = shutil.which(name)
        if found:
            return [found]

    # Linux default install
    linux = "/opt/autorecon/autorecon.py"
    if os.path.isfile(linux):
        py = shutil.which("python3") or "python3"
        return [py, linux]

    # macOS default install
    macos = os.path.expanduser("~/Tools/AutoRecon/AutoRecon.py")
    if os.path.isfile(macos):
        py = shutil.which("python3") or "python3"
        return [py, macos]

    return None


# ── Session registry ──────────────────────────────────────────────────────────
# sid -> {"proc": <process>, "queue": Queue, "pty": _PTY_TYPE | None}
_sessions: dict = {}
_lock = threading.Lock()


def _reader_thread(sid: str, proc, q: queue.Queue) -> None:
    """Read terminal output from the process and push encoded chunks to the queue."""
    try:
        while True:
            if _PTY_TYPE == "ptyprocess":
                # read() returns str; raises EOFError when the process exits
                data = proc.read(4096)

            elif _PTY_TYPE == "winpty":
                data = proc.read(4096)
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                if not data:
                    if not proc.isalive():
                        break
                    time.sleep(0.01)
                    continue

            else:
                # Plain subprocess — proc.stdout.read() returns bytes
                raw = proc.stdout.read(256)
                if not raw:
                    break
                data = raw.decode("utf-8", errors="replace")

            if data:
                q.put(data)

    except EOFError:
        pass
    except OSError:
        pass
    finally:
        with _lock:
            _sessions.pop(sid, None)
        q.put(None)   # EOF sentinel consumed by the SSE generator


# ── Routes ────────────────────────────────────────────────────────────────────

@autorecon_launch_bp.route("/")
@login_required
def index():
    cmd = find_autorecon()
    return render_template(
        "autorecon/launch.html",
        autorecon_found=(cmd is not None),
        has_pty=(_PTY_TYPE is not None),
    )


@autorecon_launch_bp.route("/launch", methods=["POST"])
@login_required
def launch():
    cmd = find_autorecon()
    if not cmd:
        return jsonify({"error": "AutoRecon not found on this system."}), 404

    data = request.get_json(silent=True) or {}
    cols = max(40, int(data.get("cols", 220)))
    rows = max(10, int(data.get("rows", 50)))

    sid = uuid.uuid4().hex
    q   = queue.Queue()

    try:
        proc = _spawn(cmd, rows, cols)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    t = threading.Thread(target=_reader_thread, args=(sid, proc, q), daemon=True)
    t.start()

    with _lock:
        _sessions[sid] = {"proc": proc, "queue": q, "pty": _PTY_TYPE}

    return jsonify({"session_id": sid})


@autorecon_launch_bp.route("/stream/<sid>")
@login_required
def stream(sid: str):
    with _lock:
        session = _sessions.get(sid)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    q = session["queue"]

    def generate():
        while True:
            try:
                chunk = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue

            if chunk is None:
                yield "data: __EOF__\n\n"
                break

            # Base64-encode: ANSI escape sequences and \r\n would break SSE framing
            encoded = base64.b64encode(chunk.encode("utf-8")).decode("ascii")
            yield f"data: {encoded}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@autorecon_launch_bp.route("/input/<sid>", methods=["POST"])
@login_required
def send_input(sid: str):
    """Receive raw terminal data from xterm.js onData (includes arrow-key escape sequences)."""
    with _lock:
        session = _sessions.get(sid)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    data = (request.get_json(silent=True) or {}).get("data", "")
    proc = session["proc"]
    try:
        if session["pty"] in ("ptyprocess", "winpty"):
            proc.write(data)
        else:
            proc.stdin.write(data.encode("utf-8"))
            proc.stdin.flush()
    except OSError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"ok": True})


@autorecon_launch_bp.route("/resize/<sid>", methods=["POST"])
@login_required
def resize(sid: str):
    """Update the PTY window size when xterm.js is resized."""
    with _lock:
        session = _sessions.get(sid)
    if not session or not session["pty"]:
        return jsonify({"ok": True})

    data = request.get_json(silent=True) or {}
    cols = max(10, int(data.get("cols", 80)))
    rows = max(5,  int(data.get("rows", 24)))
    try:
        session["proc"].setwinsize(rows, cols)
    except Exception:
        pass
    return jsonify({"ok": True})


@autorecon_launch_bp.route("/kill/<sid>", methods=["POST"])
@login_required
def kill_scan(sid: str):
    with _lock:
        session = _sessions.pop(sid, None)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    proc = session["proc"]
    try:
        if session["pty"] == "ptyprocess":
            proc.terminate(force=True)
        elif session["pty"] == "winpty":
            proc.close()
        elif os.name == "nt":
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
