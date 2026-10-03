"""Overnight GT/CG watchdog.

Watches Growtopia.exe (always on) and CreativeGrowtopia.exe (recovered after
it was seen running at least once — i.e. crash/quit reopen). When a target is
not running: collect crash info (WER 1000 events, newest minidump, newest
EpsHax crash log), relaunch, inject the no-op script, click Play Online, and
verify:
  GT — state_probe via shared EpsHax log (netid/world check).
  CG — click1 (512,389) "Online" on screen 1, click2 (678,572) "Connect" on
       the GrowID dialog, then require a fresh "Login Packet:" in the client's
       own log (%LOCALAPPDATA%\\CreativeGrowtopia\\log.txt — the game writes it
       relative to its cwd, so gt_launch.py sets cwd=game dir). EpsHax state/
       hook APIs do NOT work on CG's GT 1.47 (protocol 71): GetLocal() returns
       empty, callbacks never fire — only log()/script execution work. A window
       screenshot is saved before each attempt for coordinate debugging.
After a successful GT recovery the user suite is restored; CG gets no suite.
Single instance enforced via watchdog.lock (stacked watchdoges fight and
kill/relaunch-loop the game).

Runs ELEVATED (spawned through the elev runner). Control:
  watchdog.stop  file present -> exit
Log: coems_executor\\watchdog.log
"""
import ctypes, ctypes.wintypes as wt
import datetime, glob, os, re, subprocess, sys, time

BASE = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor"
LOG = os.path.join(BASE, "watchdog.log")
STOP = os.path.join(BASE, "watchdog.stop")
LOCK = os.path.join(BASE, "watchdog.lock")
GT_PATH = r"C:\Users\LENOVO\AppData\Local\Growtopia\Growtopia.exe"
GT_EXE = "Growtopia.exe"
CG_PATH = r"C:\Users\LENOVO\AppData\Local\CreativeGrowtopia\CreativeGrowtopia.exe"
CG_EXE = "CreativeGrowtopia.exe"
CG_LOG = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CreativeGrowtopia",
                      "log.txt")
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
RECHECK_EVERY = 60          # re-verify a running-but-unverified game
HANG_GRACE = 120            # seconds a window may be unresponsive before dump+restart
HANG_PROBE_EVERY = 20       # match main loop cadence
DUMP_KEEP = 5               # keep only the newest N hang dumps
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


def pids_for(exe):
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq %s" % exe, "/NH"],
            capture_output=True, text=True, timeout=20,
            creationflags=0x08000000)
        pids = []
        name = exe.upper()
        for ln in out.stdout.splitlines():
            if ln.upper().startswith(name):
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


def kill_target(exe):
    """Graceful kill: close main window + post WM_QUIT to its threads."""
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    pids = pids_for(exe)
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
    wlog("kill %s: pids=%s threads=%d" % (exe, pids, len(threads)))
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
        if not pids_for(exe):
            return
    wlog("WARN graceful kill did not finish, leftover pids=%s" % pids_for(exe))


def window_for(exe):
    u32 = ctypes.windll.user32
    pids = pids_for(exe)
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


def click_at(exe, x, y):
    """Foreground exe's window and left-click client point (x,y)."""
    u32 = ctypes.windll.user32
    hwnd = window_for(exe)
    if not hwnd:
        wlog("click: no %s window" % exe)
        return False
    u32.SetForegroundWindow(hwnd)
    time.sleep(1.0)
    pt = wt.POINT(x, y)
    if not u32.ClientToScreen(hwnd, ctypes.byref(pt)):
        wlog("click: ClientToScreen failed")
        return False
    u32.SetCursorPos(pt.x, pt.y)
    time.sleep(0.4)
    u32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.1)
    u32.mouse_event(0x0004, 0, 0, 0, 0)
    wlog("click %s: (%d,%d) -> screen (%d,%d) hwnd=%s"
         % (exe, x, y, pt.x, pt.y, hwnd))
    return True


def click_play(exe):
    """Click Play/Online at client (512,389) — first CG menu screen."""
    return click_at(exe, 512, 389)


def window_responsive(exe, timeout_ms=700):
    """True if the game's window pumps messages (WM_NULL probe)."""
    u32 = ctypes.windll.user32
    u32.SendMessageTimeoutW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                        ctypes.c_size_t, ctypes.c_size_t,
                                        ctypes.c_uint, ctypes.c_uint,
                                        ctypes.POINTER(ctypes.c_size_t)]
    u32.SendMessageTimeoutW.restype = ctypes.c_size_t
    hwnd = window_for(exe)
    if not hwnd:
        return True  # no window yet — the not-running path handles that
    ret = ctypes.c_size_t()
    r = u32.SendMessageTimeoutW(hwnd, 0, 0, 0, 0x0002, timeout_ms,
                                ctypes.byref(ret))  # WM_NULL, SMTO_ABORTIFHUNG
    return bool(r)


def dump_hang(exe, pid):
    """MiniDump of a wedged game for post-mortem (thread stacks included)."""
    try:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "package-scanner-output", "hang")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "%s_%s.dmp" % (exe.split(".")[0],
                                              time.strftime("%Y%m%d_%H%M%S")))
        k32 = ctypes.windll.kernel32
        dbg = ctypes.windll.dbghelp
        k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        dbg.MiniDumpWriteDump.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                          ctypes.c_char_p, ctypes.c_uint,
                                          ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p]
        dbg.MiniDumpWriteDump.restype = ctypes.c_int
        h = k32.OpenProcess(0x0010 | 0x0400, False, pid)  # VM_READ|QUERY_INFO
        if not h:
            wlog("hang dump: OpenProcess failed pid=%d err=%d"
                 % (pid, ctypes.get_last_error()))
            return None
        # MiniDumpNormal + thread info + unloaded modules (stacks for all
        # threads — enough to pinpoint the wedge without a 600MB full dump)
        ok = dbg.MiniDumpWriteDump(h, pid, path.encode("mbcs"), 0x80120,
                                   None, None, None)
        ctypes.windll.kernel32.CloseHandle(h)
        if not ok:
            wlog("hang dump: MiniDumpWriteDump failed err=%d"
                 % ctypes.get_last_error())
            return None
        wlog("hang dump: %s (%d bytes)"
             % (path, os.path.getsize(path)))
        # prune old dumps
        dumps = sorted(
            (os.path.join(d, f) for f in os.listdir(d) if f.endswith(".dmp")),
            key=os.path.getmtime)
        for old in dumps[:-DUMP_KEEP]:
            try:
                os.remove(old)
            except OSError:
                pass
        return path
    except Exception as e:
        wlog("hang dump failed: %s" % e)
        return None


def snap_window(exe, tag):
    """Save a screenshot of exe's window (CG menu debugging)."""
    try:
        from PIL import ImageGrab
        hwnd = window_for(exe)
        if not hwnd:
            wlog("snap: no %s window" % exe)
            return
        # raise first — ImageGrab captures SCREEN pixels, not the window
        ctypes.windll.user32.SetForegroundWindow(hwnd)
        time.sleep(0.8)
        rc = wt.RECT()
        if not ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rc)):
            return
        tmp = os.path.join(os.environ.get("TEMP", ""), "opencode")
        os.makedirs(tmp, exist_ok=True)
        path = os.path.join(tmp, "%s_%s.png" % (exe.split(".")[0].lower(), tag))
        ImageGrab.grab(bbox=(rc.left, rc.top, rc.right, rc.bottom),
                       all_screens=True).save(path)
        wlog("snap: %s" % path)
    except Exception as e:
        wlog("snap failed: %s" % e)


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


def verify_cg(launch_off):
    """CG login check: its own log must contain a Login Packet written after
    this cycle's launch (log truncates per launch; launch_off guards append)."""
    last_stage = "no log yet"
    for _ in range(12):
        time.sleep(5)
        try:
            with open(CG_LOG, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(launch_off if size >= launch_off else 0)
                txt = f.read().decode("utf-8", "replace")
        except Exception as e:
            last_stage = "log read failed: %s" % e
            continue
        if "Login Packet:" in txt:
            return True, "Login Packet found"
        if "Clicked Online entity" in txt:
            last_stage = "clicked Online, no Login Packet yet"
        else:
            last_stage = "no markers yet (%d bytes)" % len(txt)
    return False, last_stage


def collect_crash_info(since_ts, exe=GT_EXE):
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
        if exe == CG_EXE:
            hits = [b for b in blocks if "CreativeGrowtopia" in b]
        else:
            hits = [b for b in blocks
                    if "Growtopia" in b and "CreativeGrowtopia" not in b]
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
    # 2) newest minidump for this target in %LOCALAPPDATA%\CrashDumps
    try:
        pat = "Creative*.dmp" if exe == CG_EXE else "Growtopia*.dmp"
        dumps = sorted(glob.glob(os.path.join(DUMP_DIR, pat)),
                       key=os.path.getmtime, reverse=True)
        if dumps and os.path.getmtime(dumps[0]) > since_ts - 120:
            age = int(time.time() - os.path.getmtime(dumps[0]))
            wlog("%s minidump: %s (age %ds)"
                 % (exe, os.path.basename(dumps[0]), age))
        else:
            wlog("%s minidump: none recent" % exe)
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


def wait_for(exe, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        if pids_for(exe):
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


def relaunch_cycle(exe, fail_count):
    is_cg = exe == CG_EXE
    wlog("%s not running -> recovery (fail_count=%d)" % (exe, fail_count))
    collect_crash_info(time.time() - 120, exe)

    # backoff for repeated failures (crash loop protection)
    if fail_count:
        delay = min(BACKOFF_MAX, 15 * (2 ** min(fail_count, 5)))
        wlog("backoff %ds" % delay)
        time.sleep(delay)

    # CG log truncates on launch; size before launch = append floor
    launch_off = 0
    if is_cg:
        try:
            launch_off = os.path.getsize(CG_LOG)
        except Exception:
            launch_off = 0

    kill_target(exe)  # clear any half-dead instance
    path = CG_PATH if is_cg else GT_PATH
    r = run_py(GT_LAUNCH, [path], timeout=60)
    wlog("launch rc=%s %s" % (r.returncode, (r.stdout or "").strip()[:120]))
    if not wait_for(exe):
        wlog("FAIL %s did not start" % exe)
        return fail_count + 1
    time.sleep(8)
    r = run_py(INJECT, [NOOP, exe], timeout=200)
    wlog("inject rc=%s %s" % (r.returncode, (r.stdout or "").strip()[-300:]))
    time.sleep(3)
    for i in range(VERIFY_TRIES):
        if i:
            wlog("verify failed, retry click %d/%d" % (i, VERIFY_TRIES - 1))
        if is_cg:
            snap_window(exe, "menu%d" % i)
            click_play(exe)          # screen 1: "Online"
            time.sleep(5)
            click_at(exe, 678, 572)  # screen 2: GrowID dialog "Connect"
            ok, detail = verify_cg(launch_off)
        else:
            time.sleep(45)
            ok, detail = verify_state()
        wlog("verify: ok=%s %s" % (ok, detail))
        if ok:
            wlog("recovery SUCCESS" + (" after retry" if i else ""))
            if not is_cg:
                restore_user_script()
            return 0
    wlog("recovery FAILED after %d tries" % VERIFY_TRIES)
    return fail_count + 1


def acquire_lock():
    """Single instance: second watchdog exits instead of fighting over
    kill/relaunch cycles. Stale locks (dead pid) are taken over."""
    pid = os.getpid()
    if os.path.isfile(LOCK):
        try:
            old = int(open(LOCK).read().strip())
        except Exception:
            old = 0
        if old and old != pid:
            alive = False
            try:
                out = subprocess.run(
                    ["tasklist", "/FI", "PID eq %d" % old, "/NH"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=0x08000000)
                alive = str(old) in out.stdout
            except Exception:
                pass
            if alive:
                wlog("another watchdog already running (pid=%d) -> exit" % old)
                return False
            wlog("taking over stale lock (pid=%d dead)" % old)
    try:
        with open(LOCK, "w") as f:
            f.write(str(pid))
    except Exception as e:
        wlog("WARN cannot write lock: %s" % e)
    return True


def main():
    wlog("=== watchdog started (pid=%d, elevated=%s) ==="
         % (os.getpid(), is_elevated()))
    if not acquire_lock():
        return
    if not is_elevated():
        wlog("WARN not elevated - inject/launch will try to self-elevate (UAC)")
    # GT = always-on (historic behavior). CG = recover only after it was seen
    # running at least once this session (crash/quit reopen semantics).
    # start with fail=1 for any game already running: forces one in-place
    # verify at boot (catches manual starts / failed previous recoveries,
    # re-runs the suite, then drops back to heartbeat mode)
    targets = [
        {"exe": GT_EXE, "force": True,
         "fail": 1 if pids_for(GT_EXE) else 0,
         "was_alive": False, "last_alive": time.time(), "beat": 0.0,
         "recheck_at": 0.0, "hang_since": 0.0, "hang_probe": 0.0},
        {"exe": CG_EXE, "force": False,
         "fail": 1 if pids_for(CG_EXE) else 0,
         "was_alive": False, "last_alive": time.time(), "beat": 0.0,
         "recheck_at": 0.0, "hang_since": 0.0, "hang_probe": 0.0},
    ]
    while True:
        if os.path.exists(STOP):
            wlog("stop file present -> exit")
            return
        now = time.time()
        for t in targets:
            exe = t["exe"]
            is_cg = exe == CG_EXE
            pids = pids_for(exe)
            if pids:
                t["was_alive"] = True
                # hang watchdog: the render thread wedge (window stops
                # pumping while net threads keep logging) — capture a
                # stack dump for post-mortem, then restart to save the farm
                if now - t["hang_probe"] >= HANG_PROBE_EVERY:
                    t["hang_probe"] = now
                    if window_responsive(exe):
                        t["hang_since"] = 0.0
                    elif not t["hang_since"]:
                        t["hang_since"] = now
                        wlog("%s window NOT responding (pid=%s) — grace %ds"
                             % (exe, pids[0], HANG_GRACE))
                    elif now - t["hang_since"] >= HANG_GRACE:
                        wlog("%s unresponsive for %ds -> dump + restart"
                             % (exe, int(now - t["hang_since"])))
                        dump_hang(exe, pids[0])
                        t["hang_since"] = 0.0
                        t["fail"] = relaunch_cycle(exe, t["fail"])
                        t["beat"] = time.time()
                        t["recheck_at"] = 0.0
                        continue
                if t["fail"] == 0:
                    t["last_alive"] = now
                    if now - t["beat"] >= HEARTBEAT_EVERY:
                        wlog("healthy %s pid=%s" % (exe, pids))
                        t["beat"] = now
                elif now - t["recheck_at"] >= RECHECK_EVERY:
                    # running but never verified since the last failed
                    # recovery — re-check so a manual restart still gets
                    # login verify + suite restore + fail reset (previously
                    # this branch looped forever and watchdog gave up)
                    t["recheck_at"] = now
                    if is_cg:
                        ok, detail = verify_cg(0)
                    else:
                        ok, detail = verify_state()
                    wlog("re-verify %s: ok=%s %s" % (exe, ok, detail))
                    if ok:
                        t["fail"] = 0
                        t["last_alive"] = now
                        if not is_cg:
                            restore_user_script()
                        wlog("in-place verify SUCCESS — %s recovered" % exe)
                    elif is_cg:
                        # CG sitting at menu: same click flow as relaunch
                        click_play(exe)
                        time.sleep(5)
                        click_at(exe, 678, 572)
                        t["recheck_at"] = now + 20  # verify again sooner
            elif t["force"] or t["was_alive"]:
                wlog("%s not running (last alive %.0fs ago)"
                     % (exe, now - t["last_alive"]))
                t["fail"] = relaunch_cycle(exe, t["fail"])
                t["beat"] = time.time()
                t["recheck_at"] = 0.0
            else:
                # CG not yet seen this session — waiting for a manual start
                if now - t["beat"] >= HEARTBEAT_EVERY:
                    wlog("%s not running (waiting for manual start)" % exe)
                    t["beat"] = now
        time.sleep(20)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        wlog("watchdog crashed: %r" % e)
        raise
    finally:
        try:
            if os.path.isfile(LOCK) and open(LOCK).read().strip() == str(os.getpid()):
                os.remove(LOCK)
        except Exception:
            pass
