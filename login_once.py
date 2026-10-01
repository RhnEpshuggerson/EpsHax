"""One-shot elevated: find the Growtopia window, click play_button.png until
the game leaves the menu, snapshot each stage to temp dir. Usage:
  python login_once.py            (self-elevates; up to ~90s)
Snaps: %TEMP%/opencode/login_N.png
"""
import ctypes, ctypes.wintypes as wt, os, sys, time

SNAP_DIR = r"C:\Users\LENOVO\AppData\Local\Temp\opencode"
PNG = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\play_button.png"
NEEDLE = "Growtopia"
EXCLUDE = "Creative"
MAX_TRIES = 6

def _token_elevated():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    tken = ctypes.c_void_p()
    if not adv.OpenProcessToken(ctypes.c_void_p(-1), 8, ctypes.byref(tken)):
        return False
    e = wt.DWORD(); r = wt.DWORD()
    ok = adv.GetTokenInformation(tken, 20, ctypes.byref(e), 4, ctypes.byref(r))
    k32.CloseHandle(tken)
    return bool(ok and e.value)

if not _token_elevated():
    se = ctypes.windll.shell32.ShellExecuteW
    se.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, ctypes.c_int]
    se.restype = ctypes.c_int
    rc = se(None, "runas", sys.executable, '"%s"' % __file__, None, 1)
    sys.exit(0 if rc > 32 else 1)

import pyautogui
from PIL import ImageGrab
pyautogui.FAILSAFE = True

SCR_W = ctypes.windll.user32.GetSystemMetrics(0)
SCR_H = ctypes.windll.user32.GetSystemMetrics(1)

def find_window():
    u = ctypes.windll.user32
    out = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(hwnd, _):
        try:
            if not u.IsWindowVisible(hwnd):
                return True
            n = ctypes.create_unicode_buffer(256)
            u.GetWindowTextW(hwnd, n, 256)
            t = n.value
            if NEEDLE.lower() in t.lower() and EXCLUDE.lower() not in t.lower():
                r = wt.RECT()
                if u.GetWindowRect(hwnd, ctypes.byref(r)):
                    out.append((hwnd, r.left, r.top, r.right, r.bottom))
        except Exception:
            pass
        return True
    u.EnumWindows(WNDENUMPROC(cb), 0)
    return out[0] if out else None

def snap(w, tag):
    hwnd, l, t, r, b = w
    x = max(0, l); y = max(0, t)
    wdt = min(SCR_W, r) - x; hgt = min(SCR_H, b) - y
    if wdt <= 0 or hgt <= 0:
        return None
    p = os.path.join(SNAP_DIR, "login_%s.png" % tag)
    ImageGrab.grab(bbox=(x, y, x + wdt, y + hgt), all_screens=True).save(p)
    return p

def main():
    u = ctypes.windll.user32
    for i in range(MAX_TRIES):
        w = find_window()
        if not w:
            print("try%d: no window" % i, flush=True)
            time.sleep(5)
            continue
        hwnd = w[0]
        u.SetWindowPos(hwnd, wt.HWND(0), 0, 0, 0, 0, 0x0001 | 0x0002)
        u.SetForegroundWindow(hwnd)
        time.sleep(1)
        p = snap(w, str(i))
        x = max(0, w[1]); y = max(0, w[2])
        region = (x, y, min(SCR_W, w[3]) - x, min(SCR_H, w[4]) - y)
        clicked = False
        if region[2] > 0 and region[3] > 0:
            try:
                loc = pyautogui.locateOnScreen(PNG, confidence=0.8, region=region)
            except Exception:
                loc = None
            if loc:
                c = pyautogui.center(loc)
                print("try%d: click %s" % (i, c), flush=True)
                pyautogui.click(c)
                clicked = True
                time.sleep(12)
                snap(w, "%d_after" % i)
        print("try%d: window=%s clicked=%s snap=%s" % (i, hex(hwnd), clicked, p), flush=True)
        if clicked:
            time.sleep(8)
            w2 = find_window()
            if w2:
                snap(w2, "final")
            print("LOGIN_ONCE_DONE clicked", flush=True)
            return
        time.sleep(6)
    print("LOGIN_ONCE_DONE no_button", flush=True)

if __name__ == "__main__":
    main()
