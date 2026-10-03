"""Pipe-safe GT launcher: child gets NUL stdio, never holds the elevated
runner's stdout pipe (that deadlock wedged run_elev for 20 min).
Usage: gt_launch.py [exe-path]  (default: Growtopia.exe)"""
import os, subprocess, sys

GT = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\LENOVO\AppData\Local\Growtopia\Growtopia.exe"
nul = open(os.devnull, "rb")
nulw = open(os.devnull, "wb")
# cwd = game dir: Growtopia/CreativeGrowtopia write their own log.txt
# relative to cwd — wrong cwd makes watchdog verify look at a missing file
p = subprocess.Popen([GT], cwd=os.path.dirname(GT) or None,
                     stdin=nul, stdout=nulw, stderr=nulw,
                     creationflags=0x08000000 | 0x00000008)  # DETACHED|NO_WINDOW
print("launched pid", p.pid, flush=True)
# exit immediately: our pipe handles close, runner unblocks, GT keeps running
