"""Overnight GT watchdog.

Watches for Growtopia.exe; when it is not running: collect crash info
(WER 1000 events, newest GT minidump, newest EpsHax crash log), relaunch,
inject the no-op script (keeps EpsHax crash logger loaded), click
Play Online, and verify in-world state via state_probe.

Runs ELEVATED (spawned through the elev runner). Control:
  watchdog.stop  file present -> exit
Log: coems_executor\\watchdog.log
"""
import ctypes, ctypes.wintypes as wt
import datetime, glob, os, re, subprocess, sys, time

BASE = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor"
LOG = os.path.join(BASE, "watchdog.log")
STOP = os.path.join(BASE, "watchdog.stop")
GT_PATH = r"C:\Users\LENOVO\AppData\Local\Growtopia\Growtopia.exe"
GT_EXE = "Growtopia.exe"
GT_LOG = os.path.join(BASE, "package-scanner-output", "Cmd Log", "log.txt")
CRASH_DIR = os.path.join(BASE, "package-scanner-output", "Crash log")
DUMP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps")
NOOP = r"C:\Users\LENOVO\AppData\Local\Temp\opencode\noop.lua"
STATE_PROBE = r"C:\Users\LENOVO\AppData\Local\Temp\opencode\state_probe.lua"
USER_SCRIPT = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Growtopia",
                           "EpsScript", "coems_epshax_stub.lua")
GT_LAUNCH = os.path.join(BASE, "gt_launch.py")
INJECT = os.path.join(BASE, "inject_run.py")

HEARTBEAT_EVERY = 1800      # 30 min healthy log line
VERIFY_TRIES = 3            # click retries before kill+backoff
BACKOFF_MAX = 600


def wlog(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
            f.flush()
    except Exception:
        pass


def is_elevated():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def gt_pids():
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq %s" % GT_EXE, "/NH"],
            capture_output=True, text=True, timeout=20,
            creationflags=0x08000000)
        pids = []
        for ln in out.stdout.splitlines():
            if ln.upper().startswith("GROWTOPIA.EXE"):
                parts = ln.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    pids.append(int(parts[1]))
        return pids
    except Exception:
        return []


def run_py(script, args=(), timeout=240):
    try:
        return subprocess.run(
            [sys.executable, script] + list(args),
            capture_output=True, text=True, timeout=timeout,
            cwd=BASE, creationflags=0x08000000)
    except Exception as e:
        class R:  # duck-type
            returncode, stdout, stderr = -1, "", str(e)
        return R()


def kill_gt():
    """Graceful GT kill: close main window + post WM_QUIT to its threads."""
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    pids = gt_pids()
    if not pids:
        return
    TH32CS_SNAPTHREAD = 0x00000004
    INVALID = 0xFFFFFFFF

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ThreadID", wt.DWORD),
                    ("th32OwnerProcessID", wt.DWORD),
                    ("tpBasePri", ctypes.c_long),
                    ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", wt.DWORD)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    threads = []
    if snap != INVALID and snap != 0:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        if k32.Thread32First(snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID in pids:
                    threads.append(te.th32ThreadID)
                te.dwSize = ctypes.sizeof(te)
                if not k32.Thread32Next(snap, ctypes.byref(te)):
                    break
        k32.CloseHandle(snap)
    wlog("kill: pids=%s threads=%d" % (pids, len(threads)))
    for tid in threads:
        u32.PostThreadMessageW(tid, 0x0012, 0, 0)   # WM_QUIT
    # close visible main windows
    WNE = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @WNE
    def cb(hwnd, _):
        lp = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(lp))
        if lp.value in pids and u32.IsWindowVisible(hwnd):
            u32.PostMessageW(hwnd, 0x0010, 0, 0)   # WM_CLOSE
            u32.PostMessageW(hwnd, 0x0112, 0xF060, 0)  # SC_CLOSE
        return True
    u32.EnumWindows(cb, 0)
    for tid in threads:
        u32.PostThreadMessageW(tid, 0x0010, 0, 0)   # WM_CLOSE to threads too
    for _ in range(20):
        time.sleep(0.5)
        if not gt_pids():
            return
    wlog("WARN graceful kill did not finish, leftover pids=%s" % gt_pids())


def gt_window():
    u32 = ctypes.windll.user32
    pids = gt_pids()
    if not pids:
        return 0
    found = []
    WNE = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @WNE
    def cb(hwnd, _):
        lp = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(lp))
        if lp.value in pids and u32.IsWindowVisible(hwnd):
            found.append(hwnd)
        return True
    u32.EnumWindows(cb, 0)
    return found[0] if found else 0


def click_play():
    """Foreground GT window and click Play Online at client (512,389)."""
    u32 = ctypes.windll.user32
    hwnd = gt_window()
    if not hwnd:
        wlog("click_play: no GT window")
        return False
    u32.SetForegroundWindow(hwnd)
    time.sleep(1.0)
    pt = wt.POINT(512, 389)
    if not u32.ClientToScreen(hwnd, ctypes.byref(pt)):
        wlog("click_play: ClientToScreen failed")
        return False
    u32.SetCursorPos(pt.x, pt.y)
    time.sleep(0.4)
    u32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.1)
    u32.mouse_event(0x0004, 0, 0, 0, 0)
    wlog("click_play: clicked (%d,%d) hwnd=%s" % (pt.x, pt.y, hwnd))
    return True


def tail_log(n=262144):
    try:
        with open(GT_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - n))
            return f.read().decode("utf-8", "replace")
    except Exception:
        return ""


def verify_state():
    """Inject state_probe; return (ok, last STATE name line)."""
    r = run_py(INJECT, [STATE_PROBE, GT_EXE], timeout=180)
    if r.returncode != 0:
        return False, "inject rc=%s %s" % (r.returncode, (r.stdout or "")[-200:])
    # poll up to 40s — world load can delay script dispatch
    for _ in range(8):
        time.sleep(5)
        lines = [l for l in tail_log().splitlines()
                 if "[STATE]" in l and "netid=" in l]
        if lines:
            last = lines[-1]
            m = re.search(r"name=(.*?) netid=(-?\d+) gems=(-?\d+) world=(\S*)", last)
            ok = bool(m) and m.group(2) != "-1" and m.group(4) != ""
            return ok, last
    tail = tail_log()
    tail_lines = [l for l in tail.splitlines() if "[LUA]" in l or "[INFO]" in l]
    return False, "no STATE output; recent: %s" % (" | ".join(tail_lines[-3:])[:300])


def collect_crash_info(since_ts):
    """Append lines about why GT died to the watchdog log."""
    wlog("--- crash info ---")
    # 1) WER application event 1000 mentioning Growtopia (last ~2h)
    try:
        out = subprocess.run(
            ["wevtutil", "qe", "Application",
             "/q:*[System[(EventID=1000) and TimeCreated[timediff(@SystemTime) <= 7200000]]]",
             "/c", "5", "/rd:true", "/f:text"],
            capture_output=True, text=True, timeout=25,
            creationflags=0x08000000)
        blocks = re.split(r"Event\[\s*$|\r?\n\r?\nEvent\[", out.stdout, flags=re.M)
        hits = [b for b in blocks if "Growtopia" in b]
        if hits:
            b = hits[0]
            desc = ""
            m = re.search(r"Description:\s*(.{0,400})", b, re.S)
            if m:
                desc = " ".join(m.group(1).split())
            wlog("WER1000: %s" % desc)
        else:
            wlog("WER1000: no Growtopia event in last 2h")
    except Exception as e:
        wlog("WER query failed: %s" % e)
    # 2) newest GT minidump in %LOCALAPPDATA%\CrashDumps
    try:
        dumps = sorted(glob.glob(os.path.join(DUMP_DIR, "Growtopia*.dmp")),
                       key=os.path.getmtime, reverse=True)
        if dumps and os.path.getmtime(dumps[0]) > since_ts - 120:
            age = int(time.time() - os.path.getmtime(dumps[0]))
            wlog("GT minidump: %s (age %ds)" % (os.path.basename(dumps[0]), age))
        else:
            wlog("GT minidump: none recent")
    except Exception as e:
        wlog("dump scan failed: %s" % e)
    # 3) newest EpsHax crash log written since the watchdog last saw GT alive
    try:
        cands = glob.glob(os.path.join(CRASH_DIR, "crash*.txt")) + \
                glob.glob(os.path.join(CRASH_DIR, "crash*.dmp"))
        recent = [p for p in cands if os.path.getmtime(p) > since_ts - 120]
        if recent:
            newest = max(recent, key=os.path.getmtime)
            wlog("EpsHax crash: %s" % os.path.basename(newest))
            if newest.endswith(".txt"):
                try:
                    with open(newest, "r", encoding="utf-8", errors="replace") as f:
                        head = "".join([next(f, "") for _ in range(6)])
                    for ln in head.splitlines():
                        wlog("  | " + ln[:160])
                except Exception:
                    pass
        else:
            wlog("EpsHax crash: none since last alive")
    except Exception as e:
        wlog("crash scan failed: %s" % e)


def wait_for_gt(timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        if gt_pids():
            return True
        time.sleep(1)
    return False


def restore_user_script():
    """Re-run the user's suite after a crash-recovery so AFK work resumes."""
    if not os.path.isfile(USER_SCRIPT):
        wlog("WARN user script missing: %s" % USER_SCRIPT)
        return
    r = run_py(INJECT, [USER_SCRIPT, GT_EXE], timeout=200)
    wlog("user script inject rc=%s %s"
         % (r.returncode, (r.stdout or "").strip()[-200:]))


def relaunch_cycle(fail_count):
    wlog("GT not running -> recovery (fail_count=%d)" % fail_count)
    collect_crash_info(time.time() - 120)

    # backoff for repeated failures (crash loop protection)
    if fail_count:
        delay = min(BACKOFF_MAX, 15 * (2 ** min(fail_count, 5)))
        wlog("backoff %ds" % delay)
        time.sleep(delay)

    kill_gt()  # clear any half-dead instance
    r = run_py(GT_LAUNCH, timeout=60)
    wlog("launch rc=%s %s" % (r.returncode, (r.stdout or "").strip()[:120]))
    if not wait_for_gt():
        wlog("FAIL GT did not start")
        return fail_count + 1
    time.sleep(8)
    r = run_py(INJECT, [NOOP, GT_EXE], timeout=200)
    wlog("inject rc=%s %s" % (r.returncode, (r.stdout or "").strip()[-300:]))
    time.sleep(3)
    click_play()
    time.sleep(45)
    ok, detail = verify_state()
    wlog("verify: ok=%s %s" % (ok, detail))
    if ok:
        wlog("recovery SUCCESS")
        restore_user_script()
        return 0
    # menu might have been missed — try clicking again
    for i in range(1, VERIFY_TRIES):
        wlog("verify failed, retry click %d/%d" % (i, VERIFY_TRIES - 1))
        click_play()
        time.sleep(45)
        ok, detail = verify_state()
        wlog("verify: ok=%s %s" % (ok, detail))
        if ok:
            wlog("recovery SUCCESS after retry")
            restore_user_script()
            return 0
    wlog("recovery FAILED after %d tries" % VERIFY_TRIES)
    return fail_count + 1


def main():
    wlog("=== watchdog started (pid=%d, elevated=%s) ==="
         % (os.getpid(), is_elevated()))
    if not is_elevated():
        wlog("WARN not elevated - inject/launch will try to self-elevate (UAC)")
    fail_count = 0
    last_alive = time.time()
    last_beat = 0.0
    while True:
        if os.path.exists(STOP):
            wlog("stop file present -> exit")
            return
        pids = gt_pids()
        now = time.time()
        if pids:
            if fail_count == 0:
                last_alive = now
                if now - last_beat >= HEARTBEAT_EVERY:
                    wlog("healthy pid=%s" % pids)
                    last_beat = now
            else:
                # GT running but we never got a good verify — leave it alone
                # for a couple minutes, then re-check (it may be mid-load)
                time.sleep(30)
        else:
            wlog("GT not running (last alive %.0fs ago)" % (now - last_alive))
            fail_count = relaunch_cycle(fail_count)
            last_beat = time.time()
        time.sleep(20)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        wlog("watchdog crashed: %r" % e)
        raise
