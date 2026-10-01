"""Detached launcher: starts watchdog.py with NUL stdio so it never holds
the elevated runner's output pipe open (that wedged the runner for the
whole night once). Usage: python start_watchdog.py"""
import os, subprocess, sys

WATCHDOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watchdog.py")
nul = open(os.devnull, "rb")
nulw = open(os.devnull, "wb")
pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
if not os.path.isfile(pythonw):
    pythonw = "pythonw.exe"
p = subprocess.Popen([pythonw, WATCHDOG], stdin=nul, stdout=nulw, stderr=nulw,
                     creationflags=0x08000000 | 0x00000008)  # DETACHED|NO_WINDOW
print("watchdog pid", p.pid, flush=True)
