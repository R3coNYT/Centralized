"""
Windows Service wrapper for Centralized.

Usage (run as Administrator):
  Install :  python centralized_service.py install
  Start   :  sc start Centralized       (or Start-Service Centralized)
  Stop    :  sc stop  Centralized       (or Stop-Service Centralized)
  Remove  :  python centralized_service.py remove

To stop the service and prevent auto-start on next reboot:
  Set-Service Centralized -StartupType Manual; Stop-Service Centralized

To re-enable auto-start:
  Set-Service Centralized -StartupType Automatic; Start-Service Centralized
"""

import os
import sys

# Absolute path of the Centralized install directory (where app.py lives)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Activate the virtualenv for the service process ───────────────────────────
# pythonservice.exe uses the *base* Python, not the venv Python, so it cannot
# find pywin32, Flask, waitress, etc. unless we prepend the venv paths manually.
_venv_site = os.path.join(BASE_DIR, "venv", "Lib", "site-packages")
if os.path.isdir(_venv_site):
    sys.path.insert(0, _venv_site)
    # pywin32 .pyd extensions live in site-packages\win32\
    _win32_dir = os.path.join(_venv_site, "win32")
    if os.path.isdir(_win32_dir):
        sys.path.insert(0, _win32_dir)
    # Python 3.8+ uses a restricted DLL search: add pywin32 DLL dirs explicitly
    if hasattr(os, "add_dll_directory"):
        for _dll_dir in (
            os.path.join(_venv_site, "pywin32_system32"),
            os.path.join(_venv_site, "win32"),
        ):
            if os.path.isdir(_dll_dir):
                os.add_dll_directory(_dll_dir)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
# ─────────────────────────────────────────────────────────────────────────────

import socket

import servicemanager
import win32event
import win32service
import win32serviceutil

SERVICE_NAME    = "Centralized"
SERVICE_DISPLAY = "Centralized - Pentest Audit Platform"
SERVICE_DESC    = (
    "R3coNYT Centralized pentest audit management platform. "
    "Web UI available at http://127.0.0.1:5000"
)

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 5000))


class CentralizedService(win32serviceutil.ServiceFramework):
    _svc_name_         = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_  = SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self._server = None

    # Called by SCM when the service is stopped
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self._server is not None:
            self._server.close()
        win32event.SetEvent(self._stop_event)

    # Called by SCM to run the service
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._run()

    def _run(self):
        os.chdir(BASE_DIR)
        try:
            from app import create_app
            from waitress import create_server

            app = create_app()
            self._server = create_server(app, host=HOST, port=PORT)
            servicemanager.LogInfoMsg(
                f"Centralized listening on {HOST}:{PORT}"
            )
            self._server.run()  # blocks until SvcStop() calls server.close()
        except Exception as exc:
            servicemanager.LogErrorMsg(f"Centralized service error: {exc}")
        finally:
            win32event.SetEvent(self._stop_event)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Invoked directly by the Service Control Manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CentralizedService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command-line management: install / start / stop / remove …
        win32serviceutil.HandleCommandLine(CentralizedService)
