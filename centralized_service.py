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

# Ensure the install directory is always on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

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
