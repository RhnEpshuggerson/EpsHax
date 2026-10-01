"""Pipe-safe GT launcher: child gets NUL stdio, never holds the elevated
runner's stdout pipe (that deadlock wedged run_elev for 20 min)."""
import os, subprocess, sys

GT = r"C:\Users\LENOVO\AppData\Local\Growtopia\Growtopia.exe"
nul = open(os.devnull, "rb")
nulw = open(os.devnull, "wb")
p = subprocess.Popen([GT], stdin=nul, stdout=nulw, stderr=nulw,
                     creationflags=0x08000000 | 0x00000008)  # DETACHED|NO_WINDOW
print("launched pid", p.pid, flush=True)
# exit immediately: our pipe handles close, runner unblocks, GT keeps running
