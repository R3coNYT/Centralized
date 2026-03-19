"""
AutoRecon interactive terminal via SSE — with persistent session replay.

Sessions survive page reloads: the process keeps running on the server and
all output is buffered so reconnecting clients receive a full replay followed
by live streaming.  Multiple browser tabs can connect to the same session
simultaneously.

PTY support (strongly recommended):
  Windows  : pip install pywinpty>=2.0
  Linux/mac: pip install ptyprocess>=0.7
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
    if _PTY_TYPE == "ptyprocess":
        return _PtyProcess.spawn(cmd, dimensions=(rows, cols))

    if _PTY_TYPE == "winpty":
        cmdlist = list(cmd)
        if cmdlist[0].lower().endswith(".bat"):
            cmdlist = ["cmd.exe", "/C"] + cmdlist
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmdlist)
        return _winpty.PtyProcess.spawn(cmd_str, dimensions=(rows, cols))

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
    if os.name == "nt":
        bat = r"C:\Tools\AutoRecon\AutoRecon.bat"
        if os.path.isfile(bat):
            return [bat]

    for name in ("AutoRecon", "autorecon"):
        found = shutil.which(name)
        if found:
            return [found]

    linux = "/opt/autorecon/autorecon.py"
    if os.path.isfile(linux):
        py = shutil.which("python3") or "python3"
        return [py, linux]

    macos = os.path.expanduser("~/Tools/AutoRecon/AutoRecon.py")
    if os.path.isfile(macos):
        py = shutil.which("python3") or "python3"
        return [py, macos]

    return None


# ── Session registry ──────────────────────────────────────────────────────────
#
# sid -> {
#   "proc":        <process>,
#   "pty":         "winpty" | "ptyprocess" | None,
#   "output_buf":  list[str],        # all output chunks — replayed to reconnecting clients
#   "buf_lock":    threading.Lock,   # guards output_buf, alive, subscribers
#   "alive":       bool,             # False once the process exits
#   "ended_at":    float | None,     # time.time() when process ended
#   "subscribers": list[Queue],      # one Queue per connected SSE client
# }
_sessions: dict = {}
_lock = threading.Lock()

_ENDED_TTL = 7200   # keep completed sessions 2 h for replay


def _prune_ended_sessions() -> None:
    """Remove ended sessions older than TTL.  Must be called while holding _lock."""
    cutoff = time.time() - _ENDED_TTL
    stale = [sid for sid, s in _sessions.items()
             if not s["alive"] and s["ended_at"] and s["ended_at"] < cutoff]
    for sid in stale:
        _sessions.pop(sid)


def _reader_thread(sid: str, proc, session: dict) -> None:
    """Read process output, buffer it, and fan-out to all subscribed SSE clients."""
    try:
        while True:
            if _PTY_TYPE == "ptyprocess":
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
                raw = proc.stdout.read(256)
                if not raw:
                    break
                data = raw.decode("utf-8", errors="replace")

            if data:
                with session["buf_lock"]:
                    session["output_buf"].append(data)
                    for q in session["subscribers"]:
                        q.put(data)

    except EOFError:
        pass
    except OSError:
        pass
    finally:
        with session["buf_lock"]:
            session["alive"] = False
            session["ended_at"] = time.time()
            for q in session["subscribers"]:
                q.put(None)          # EOF sentinel to each live client
            session["subscribers"].clear()


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

    session: dict = {
        "proc":        None,
        "pty":         _PTY_TYPE,
        "output_buf":  [],
        "buf_lock":    threading.Lock(),
        "alive":       True,
        "ended_at":    None,
        "subscribers": [],
    }

    try:
        proc = _spawn(cmd, rows, cols)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    session["proc"] = proc

    t = threading.Thread(target=_reader_thread, args=(sid, proc, session), daemon=True)
    t.start()

    with _lock:
        _prune_ended_sessions()
        _sessions[sid] = session

    return jsonify({"session_id": sid})


@autorecon_launch_bp.route("/status/<sid>")
@login_required
def session_status(sid: str):
    """Return the alive state of a single session."""
    with _lock:
        session = _sessions.get(sid)
    if not session:
        return jsonify({"exists": False, "alive": False})
    return jsonify({
        "exists":   True,
        "alive":    session["alive"],
        "buf_size": len(session["output_buf"]),
    })


@autorecon_launch_bp.route("/stream/<sid>")
@login_required
def stream(sid: str):
    with _lock:
        session = _sessions.get(sid)

    if not session:
        def _eof():
            yield "data: __EOF__\n\n"
        return Response(
            stream_with_context(_eof()),
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    client_q: queue.Queue = queue.Queue()

    # Atomically snapshot the buffer and register as a live subscriber
    with session["buf_lock"]:
        buffered = list(session["output_buf"])
        is_alive = session["alive"]
        if is_alive:
            session["subscribers"].append(client_q)

    def generate():
        # 1. Replay all buffered output
        for chunk in buffered:
            yield "data: {}\n\n".format(
                base64.b64encode(chunk.encode("utf-8")).decode("ascii")
            )

        if not is_alive:
            yield "data: __EOF__\n\n"
            return

        # 2. Live stream new chunks as they arrive
        try:
            while True:
                try:
                    chunk = client_q.get(timeout=30)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue

                if chunk is None:
                    yield "data: __EOF__\n\n"
                    break

                yield "data: {}\n\n".format(
                    base64.b64encode(chunk.encode("utf-8")).decode("ascii")
                )
        finally:
            # Remove this client's queue on disconnect/close
            with session["buf_lock"]:
                try:
                    session["subscribers"].remove(client_q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@autorecon_launch_bp.route("/input/<sid>", methods=["POST"])
@login_required
def send_input(sid: str):
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
    # Remove from registry immediately (no replay after explicit kill)
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
