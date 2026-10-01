import ctypes, ctypes.wintypes as wt, struct, sys

OUT = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor\package-scanner-output\probe_result.txt"

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

if not _token_elevated():
    try:
        open(OUT, "w", encoding="utf-8").close()
    except Exception:
        pass
    print("not elevated - requesting administrator (UAC)...", flush=True)
    se = ctypes.windll.shell32.ShellExecuteW
    se.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, ctypes.c_int]
    se.restype = ctypes.c_int
    rc = se(None, "runas", sys.executable, '"%s"' % __file__, None, 1)
    print("ShellExecuteW rc=%d" % rc, flush=True)
    sys.exit(0 if rc > 32 else 1)

lines = []
def log(m):
    lines.append(str(m))
    print(m, flush=True)

try:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED = 0x1000

    tken = ctypes.c_void_p()
    adv.OpenProcessToken(ctypes.c_void_p(-1), 0x0020 | 0x0008, ctypes.byref(tken))
    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]
    class TP(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID), ("Attributes", wt.DWORD)]
    tp = TP(); tp.PrivilegeCount = 1
    adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tp.Luid))
    tp.Attributes = 2
    adv.AdjustTokenPrivileges(tken, False, ctypes.byref(tp), 0, None, None)
    k32.CloseHandle(tken)

    k32.OpenProcess.restype = ctypes.c_void_p
    target_pid = None
    pids = (wt.DWORD * 8192)(); need = wt.DWORD()
    psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(need))
    for pid in pids[: need.value // 4]:
        if not pid: continue
        hh = k32.OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, False, pid)
        if not hh: continue
        n = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(hh, None, n, 260)
        if n.value.lower() == "growtopia.exe":
            target_pid = pid; break
        k32.CloseHandle(hh)
    if not target_pid:
        raise RuntimeError("Growtopia.exe not found")
    log("pid=%d" % target_pid)

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, target_pid)
    if not h:
        raise RuntimeError("OpenProcess err=%d" % ctypes.get_last_error())

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wt.DWORD),
                    ("EntryPoint", ctypes.c_void_p)]
    psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_void_p, wt.DWORD]
    psapi.GetModuleInformation.restype = wt.BOOL
    arr = (ctypes.c_void_p * 512)()
    psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(need), 0x03)
    mods = []
    for base in arr[: need.value // ctypes.sizeof(ctypes.c_void_p)]:
        nm = ctypes.create_unicode_buffer(260)
        psapi.GetModuleFileNameExW(h, ctypes.c_void_p(base), nm, 260)
        mi = MODULEINFO()
        psapi.GetModuleInformation(h, ctypes.c_void_p(base), ctypes.byref(mi), ctypes.sizeof(mi))
        mods.append((nm.value, (base or 0), mi.SizeOfImage or 0))
    log("modules=%d" % len(mods))
    for nm, b, sz in mods:
        low = nm.lower()
        if "epshax" in low or "growpai" in low or "minhook" in low:
            log("  mod %s @0x%X size=0x%X" % (nm, b, sz))

    def mod_of(addr):
        for nm, b, sz in mods:
            if b <= addr < b + sz:
                return "%s+0x%X" % (nm.split("\\")[-1], addr - b)
        return "OUTSIDE-ALL-MODULES"

    def rd(addr, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t()
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
            return None
        return bytes(buf.raw[: got.value])

    def ru64(addr):
        b = rd(addr, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else 0

    # ---- relay chain analysis (whose handler?)
    lfm = 0x14145F590
    code = rd(lfm, 16)
    if code and code[0] == 0xE9:
        tgt = lfm + 5 + struct.unpack("<i", code[1:5])[0]
        slot_code = rd(tgt, 16)
        handler = 0
        if slot_code and slot_code[0:2] == b"\xff\x25":
            handler = ru64(tgt + 6)
        log("LoadFromMem relay: target=0x%X (%s) handler=0x%X (%s)" %
            (tgt, mod_of(tgt), handler, mod_of(handler)))
        # region info for the relay page
        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                        ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
        mbi = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(tgt), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            log("relay region: base=0x%X allocbase=0x%X size=0x%X prot=0x%X state=0x%X" %
                ((mbi.BaseAddress or 0), (mbi.AllocationBase or 0), mbi.RegionSize,
                 mbi.Protect, mbi.State))

    # ---- GetCtx decode (fixed): sub rsp,28 | call A | mov rcx,rax | call B | add rsp,28 | ret
    g = 0x140B2D9D0
    gc = rd(g, 64)
    log("GetCtx code: %s" % (gc.hex() if gc else "?"))
    ctx = 0
    if gc:
        i = 0
        rcx_val = 0
        last = 0
        while i < len(gc) - 6:
            if gc[i:i+3] == b"\x48\x83\xec" or gc[i:i+3] == b"\x48\x83\xc4":
                i += 4; continue
            if gc[i:i+3] == b"\x48\x8b\xc8":          # mov rcx,rax
                rcx_val = last
                i += 3; continue
            if gc[i] == 0xC3:
                break
            if gc[i] == 0xE8:
                disp = struct.unpack("<i", gc[i+1:i+5])[0]
                ta = g + i + 5 + disp
                c = rd(ta, 24)
                log("  call 0x%X (%s): %s" % (ta, mod_of(ta), c.hex() if c else "?"))
                val = 0
                if c:
                    if c[0:3] == b"\x48\x8b\x05":      # mov rax,[rip+disp32]
                        d2 = struct.unpack("<i", c[3:7])[0]
                        glob = ta + 7 + d2
                        val = ru64(glob)
                        log("    -> global@0x%X = 0x%X" % (glob, val))
                    elif c[0:3] == b"\x48\x8b\x81":    # mov rax,[rcx+disp32]
                        d2 = struct.unpack("<i", c[3:7])[0]
                        base = rcx_val if rcx_val else last
                        val = ru64(base + d2)
                        log("    -> [0x%X+0x%X] = 0x%X" % (base, d2, val))
                    elif c[0:3] == b"\x48\x8b\x01":    # mov rax,[rcx]
                        val = ru64(rcx_val if rcx_val else last)
                        log("    -> [rcx] = 0x%X" % val)
                    elif c[0] == 0xE9:
                        t2 = ta + 5 + struct.unpack("<i", c[1:5])[0]
                        c3 = rd(t2, 16)
                        log("    -> thunk 0x%X (%s): %s" % (t2, mod_of(t2), c3.hex() if c3 else "?"))
                        for hop in range(2):
                            if c3 and c3[0:3] == b"\x48\x8b\x05":
                                d2 = struct.unpack("<i", c3[3:7])[0]
                                glob = t2 + 7 + d2
                                val = ru64(glob)
                                log("    -> global@0x%X = 0x%X" % (glob, val))
                                break
                            if c3 and c3[0] == 0xE9:
                                t2 = t2 + 5 + struct.unpack("<i", c3[1:5])[0]
                                c3 = rd(t2, 16)
                                log("    -> thunk2 0x%X (%s): %s" % (t2, mod_of(t2), c3.hex() if c3 else "?"))
                                continue
                            break
                last = val
                i += 5; continue
            log("  unhandled %02X at +%d" % (gc[i], i))
            break
        ctx = last
    log("ctx=0x%X" % ctx)

    if ctx:
        world = ru64(ctx + 0x110)
        log("world=0x%X (%s)" % (world, mod_of(world)))
        if world:
            wh = rd(world + 0x90, 8)
            w = hh = 0
            if wh and len(wh) == 8:
                w, hh = struct.unpack("<II", wh)
            log("w=%d h=%d" % (w, hh))
            be = rd(world + 0xA0, 16)
            if be and len(be) == 16:
                begin, end = struct.unpack("<QQ", be)
                span = end - begin if end > begin else 0
                need = w * hh * 0xF0
                log("begin=0x%X end=0x%X span=0x%X need=0x%X ok=%s" %
                    (begin, end, span, int(need), span >= need and need > 0))
                if begin and span > 0:
                    t = rd(begin, 16)
                    log("tile0: %s" % (t.hex() if t else "READ FAIL"))
            blob = rd(world, 0x400)
            if blob:
                i = 0; strs = []
                while i < len(blob):
                    if 32 <= blob[i] < 127:
                        j = i
                        while j < len(blob) and 32 <= blob[j] < 127: j += 1
                        if j - i >= 4: strs.append("+0x%X=%r" % (i, blob[i:j]))
                        i = j
                    else:
                        i += 1
                log("world strings: " + " | ".join(strs[:25]))
                p = blob.find(b"BUYDTA")
                if p >= 0:
                    log("NAME SSO at world+0x%X" % p)
                for off in range(0, 0x3C0, 8):
                    if off + 0x18 > len(blob): break
                    sz = struct.unpack_from("<Q", blob, off + 0x10)[0]
                    if sz == 6:
                        ptr = struct.unpack_from("<Q", blob, off)[0]
                        s = rd(ptr, 8) if ptr else None
                        if s and s[:6] == b"BUYDTA":
                            log("NAME heap-string at world+0x%X (ptr=0x%X)" % (off, ptr))
except Exception as e:
    log("ERROR: %r" % (e,))

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
if sys.stdout is not None and sys.stdout.isatty():
    try:
        input("\n[Enter to close]")
    except Exception:
        pass
