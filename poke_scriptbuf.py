import ctypes, ctypes.wintypes as wt, struct, sys

NEW_PATH = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\Script\auto_geiger.lua"
OUT_PATH = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor\package-scanner-output\poke_result.txt"

# ── self-elevation: the game runs elevated, so we must too ──────────
def _token_elevated():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    tken = ctypes.c_void_p()
    if not adv.OpenProcessToken(ctypes.c_void_p(-1), 8, ctypes.byref(tken)):
        return False
    elev = wt.DWORD(); ret = wt.DWORD()
    ok = adv.GetTokenInformation(tken, 20, ctypes.byref(elev), 4, ctypes.byref(ret))
    k32.CloseHandle(tken)
    return bool(ok and elev.value)

def _write_out(text):
    try:
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass

if not _token_elevated():
    try:
        open(OUT_PATH, "w", encoding="utf-8").close()
    except Exception:
        pass
    msg = "not elevated - requesting administrator (UAC)..."
    print(msg, flush=True)
    _write_out(msg)
    se = ctypes.windll.shell32.ShellExecuteW
    se.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR,
                   wt.LPCWSTR, ctypes.c_int]
    se.restype = ctypes.c_int
    rc = se(None, "runas", sys.executable, '"%s"' % __file__, None, 1)
    line = "ShellExecuteW runas rc=%d (script=%s exe=%s)" % (
        rc, __file__, sys.executable)
    print(line, flush=True)
    _write_out(line)
    if rc <= 32:
        msg = "UAC declined or failed - cannot poke the elevated game without admin"
        print(msg, flush=True)
        _write_out(msg)
    sys.exit(0 if rc > 32 else 1)

log_lines = []
def log(msg):
    log_lines.append(str(msg))
    print(msg, flush=True)
    try:
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")
    except Exception:
        pass
try:
    open(OUT_PATH, "w", encoding="utf-8").close()
except Exception:
    pass

def parse_exports(img):
    """Return {name: rva} from a remote MAPPED PE image (buffer off == RVA)."""
    e = struct.unpack_from("<I", img, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", img, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    erva, esz = struct.unpack_from("<II", img, dd)
    if not erva:
        return {}
    def r2o(rva):
        if 0 <= rva and rva + 8 <= len(img):
            return rva
        return None
    ed = r2o(erva)
    if ed is None:
        return {}
    nn = struct.unpack_from("<I", img, ed + 24)[0]
    names = struct.unpack_from("<I", img, ed + 32)[0]
    ords_ = struct.unpack_from("<I", img, ed + 36)[0]
    funcs = struct.unpack_from("<I", img, ed + 28)[0]
    out = {}
    for i in range(nn):
        nr = struct.unpack_from("<I", img, r2o(names) + i * 4)[0]
        nm = img[r2o(nr):].split(b"\x00")[0].decode(errors="replace")
        ord_i = struct.unpack_from("<H", img, r2o(ords_) + i * 2)[0]
        frva = struct.unpack_from("<I", img, r2o(funcs) + ord_i * 4)[0]
        out[nm] = frva
    return out

try:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)

    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_QUERY_INFORMATION = 0x0400
    RIGHTS = (PROCESS_VM_READ | PROCESS_VM_WRITE |
              PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)

    # diagnostics: token elevation of this process
    class TOKEN_ELEVATION(ctypes.Structure):
        _fields_ = [("TokenIsElevated", wt.DWORD)]
    try:
        tken = ctypes.c_void_p()
        TOKEN_QUERY = 0x0008
        if adv.OpenProcessToken(ctypes.c_void_p(-1), TOKEN_QUERY, ctypes.byref(tken)):
            elev = TOKEN_ELEVATION()
            ret = wt.DWORD()
            adv.GetTokenInformation(tken, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret))
            log("self elevated: %s" % bool(elev.TokenIsElevated))
            k32.CloseHandle(tken)
        else:
            log("OpenProcessToken failed err=%d" % ctypes.get_last_error())
    except Exception as e:
        log("elev diag failed: %r" % e)

    # enable SeDebugPrivilege
    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID), ("Attributes", wt.DWORD)]
    try:
        tken = ctypes.c_void_p()
        if adv.OpenProcessToken(ctypes.c_void_p(-1),
                                0x0020 | 0x0008, ctypes.byref(tken)):  # ADJUST|QUERY
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tp.Luid)):
                tp.Attributes = 0x00000002
                adv.AdjustTokenPrivileges(tken, False, ctypes.byref(tp), 0, None, None)
                log("SeDebug enable: err=%d" % ctypes.get_last_error())
            k32.CloseHandle(tken)
    except Exception as e:
        log("sedebug failed: %r" % e)

    # 1. find the process that has EpsHax.dll loaded
    #    phase A: probe-style enumeration (QUERY_LIMITED|VM_READ — known good)
    #    phase B: reopen only the match with full VM_WRITE rights
    k32.OpenProcess.restype = ctypes.c_void_p
    ENUM_RIGHTS = 0x0010 | 0x1000   # VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
    candidates = []
    pids = (wt.DWORD * 4096)()
    need = wt.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(need)):
        raise OSError(ctypes.get_last_error(), "EnumProcesses failed")
    npid = need.value // ctypes.sizeof(wt.DWORD)
    log("phase A: scanning %d pids (limited rights)" % npid)
    done = 0
    for pid in pids[: npid]:
        if pid == 0:
            continue
        h = k32.OpenProcess(ENUM_RIGHTS, False, pid)
        if not h:
            continue
        arr = (ctypes.c_void_p * 1024)()
        if psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr),
                                      ctypes.byref(need), 0x03):
            for base in arr[: need.value // ctypes.sizeof(ctypes.c_void_p)]:
                name = ctypes.create_unicode_buffer(260)
                psapi.GetModuleFileNameExW(h, ctypes.c_void_p(base), name, 260)
                if name.value.lower().endswith("epshax.dll"):
                    pname = ctypes.create_unicode_buffer(260)
                    psapi.GetModuleBaseNameW(h, ctypes.c_void_p(base), pname, 260)
                    candidates.append((pid, base, pname.value))
                    break
        k32.CloseHandle(h)
        done += 1
        if done % 200 == 0:
            log("  ...scanned %d/%d" % (done, npid))
    log("phase A done: %d candidate(s)" % len(candidates))

    if not candidates:
        raise RuntimeError("no running process has EpsHax.dll loaded "
                           "(start the game via EpsHaxLoader first)")
    candidates.sort(key=lambda c: ("growtopia.exe" not in c[2].lower(), c[2]))
    log("phase B: reopening pid=%d with VM_WRITE rights" % candidates[0][0])
    PID, target, pname = candidates[0]
    h = k32.OpenProcess(RIGHTS, False, PID)
    if not h:
        raise OSError(ctypes.get_last_error(), "OpenProcess(full rights) failed")
    log("target: pid=%d exe=%s EpsHax.dll base=0x%X" % (PID, pname, target))
    if len(candidates) > 1:
        log("note: %d candidates, picked %s" % (len(candidates), pname))

    # 2. read module image (header first, then full)
    hdr = ctypes.create_string_buffer(0x400)
    n = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(target), hdr, 0x400, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "header read failed")
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", hdr, e_lfanew + 80)[0]
    log("SizeOfImage = 0x%X" % size_of_image)

    log("phase C: reading full image")
    img = ctypes.create_string_buffer(size_of_image)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(target), img, size_of_image, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "image read failed")
    data = bytes(img.raw[:n.value])

    # 3. locate scriptBuf: resolve exported getter -> buffer address
    log("phase D: resolving export")
    exports = parse_exports(data)
    script_addr = None
    if "EpsHax_GetScriptBuf" in exports:
        frva = exports["EpsHax_GetScriptBuf"]
        code = data[frva:frva + 16]
        hops = 0
        while len(code) >= 5 and code[0] == 0xE9 and hops < 8:
            frva = frva + 5 + struct.unpack_from("<i", code, 1)[0]
            code = data[frva:frva + 16]
            hops += 1
        buf_rva = None
        p = code.find(b"\x48\x8d\x05")   # lea rax,[rip+disp32]
        if 0 <= p and p + 7 <= len(code):
            disp = struct.unpack_from("<i", code, p + 3)[0]
            buf_rva = frva + p + 7 + disp
        if buf_rva is None or not (0 <= buf_rva and buf_rva + 262144 <= size_of_image):
            raise RuntimeError("cannot resolve scriptBuf from export "
                               "(code=%s buf_rva=%r)" % (code[:8].hex(), buf_rva))
        script_addr = target + buf_rva
        log("via export EpsHax_GetScriptBuf -> scriptBuf @0x%X (rva 0x%X, %d thunk hops)"
            % (script_addr, buf_rva, hops))
    else:
        log("export not present (old DLL?) — falling back to content scan")

    with open(NEW_PATH, "rb") as f:
        new_bytes = f.read()
    if len(new_bytes) >= 262144:
        raise RuntimeError("script too big for scriptBuf (%d)" % len(new_bytes))
    sig = new_bytes.split(b"\n")[0].rstrip(b"\r")
    log("new script: %d bytes, line1=%r" % (len(new_bytes), sig))

    NEW_MARK = b"RING_SILENT_S"
    OLD_MARK = b"no color change in 20s"
    if NEW_MARK not in new_bytes:
        raise RuntimeError("sanity: new file missing %r" % NEW_MARK)
    if OLD_MARK in new_bytes:
        raise RuntimeError("sanity: new file still has old mark")
    if b"walkWatch" not in new_bytes:
        raise RuntimeError("sanity: new file missing walkWatch")

    if script_addr is None:
        # find NUL-terminated block holding a previous auto_geiger copy
        marker = b"auto_geiger: geiger world="
        off, found = 0, []
        while True:
            i = data.find(marker, off)
            if i < 0:
                break
            prev = data.rfind(b"\x00", 0, i)
            start = 0 if prev < 0 else prev + 1
            end = data.find(b"\x00", i)
            block = data[start:end]
            log("content candidate @module+0x%X len=%d" % (start, len(block)))
            if sig in block[:200] and 8000 < len(block) < 262144:
                found.append(start)
            off = i + 1
        if not found:
            raise RuntimeError("scriptBuf not found: no export and no prior "
                               "script content in module")
        script_addr = target + found[0]
        log("via content scan -> 0x%X" % script_addr)

    # 4. write + verify
    out = new_bytes + b"\x00"
    log("phase E: writing %d bytes to 0x%X" % (len(out), script_addr))
    wr = ctypes.c_size_t()
    if not k32.WriteProcessMemory(h, ctypes.c_void_p(script_addr),
                                  out, len(out), ctypes.byref(wr)):
        raise OSError(ctypes.get_last_error(), "WriteProcessMemory failed")
    log("wrote %d bytes" % wr.value)

    chk = ctypes.create_string_buffer(len(out))
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(script_addr), chk, len(out), ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "readback failed")
    rb = bytes(chk.raw[:n.value])
    assert rb.startswith(sig), "readback line1 mismatch"
    assert NEW_MARK in rb and b"session dead" in rb, "new markers missing"
    assert rb.split(b"\x00")[0] == new_bytes, "readback content mismatch"
    log("VERIFIED: scriptBuf @0x%X holds the patched auto_geiger.lua (%d bytes)"
        % (script_addr, len(new_bytes)))
    k32.CloseHandle(h)
    rc = 0
except Exception as e:
    log("ERROR: %r" % (e,))
    rc = 1

with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines) + "\n")
if sys.stdout is not None and sys.stdout.isatty():
    try:
        input("\n[Enter to close]")
    except Exception:
        pass
sys.exit(rc)
