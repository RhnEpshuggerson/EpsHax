"""Inject EpsHax.dll into the running CreativeGrowtopia/Growtopia process
(if not already loaded), then poke a script into scriptBuf and execute it
headlessly via the EpsHax_ExecuteScriptBuf export.

  python inject_run.py <script-path>
Self-elevates (game is elevated). Exit 0 = injected+script started.
"""
import ctypes, ctypes.wintypes as wt, os, struct, sys, time

OUT_PATH = (r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor"
            r"\package-scanner-output\poke_result.txt")
_DBG = r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor\build\Debug"
# newest built DLL — EpsHax2/3.dll exist while other builds are file-locked
# by loaded processes; EpsHax3 is the current instrumented build
_candidates = [os.path.join(_DBG, n)
                               for n in ("EpsHax10.dll", "EpsHax9.dll", "EpsHax8.dll", "EpsHax7.dll", "EpsHax6.dll", "EpsHax5.dll", "EpsHax4.dll", "EpsHax3.dll", "EpsHax2.dll", "EpsHax.dll")]
DLL_PATH = max((p for p in _candidates if os.path.isfile(p)),
               key=os.path.getmtime, default=_candidates[0])

if len(sys.argv) < 2:
    print("usage: inject_run.py <script-path> [target-exe]", flush=True)
    sys.exit(2)
NEW_PATH = sys.argv[1]
TARGET_EXE = sys.argv[2] if len(sys.argv) > 2 else None

def _write_out(text):
    try:
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass

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
    try:
        open(OUT_PATH, "w", encoding="utf-8").close()
    except Exception:
        pass
    se = ctypes.windll.shell32.ShellExecuteW
    se.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR,
                   wt.LPCWSTR, ctypes.c_int]
    se.restype = ctypes.c_void_p
    args = '"%s" "%s"' % (__file__, NEW_PATH)
    if TARGET_EXE:
        args += ' "%s"' % TARGET_EXE  # keep target across elevation
    rc = se(None, "runas", sys.executable, args, None, 1)
    print("ShellExecuteW runas rc=%d" % rc, flush=True)
    _write_out("ShellExecuteW runas rc=%d" % rc)
    sys.exit(0 if rc > 32 else 1)

def log(msg):
    print(msg, flush=True)
    _write_out(msg)

try:
    open(OUT_PATH, "w", encoding="utf-8").close()
except Exception:
    pass

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_ulong, ctypes.c_ulong]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = ctypes.c_int
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_int
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.WaitForSingleObject.restype = wt.DWORD

# SeDebugPrivilege
try:
    tken = ctypes.c_void_p()
    if adv.OpenProcessToken(ctypes.c_void_p(-1), 0x0020 | 0x0008, ctypes.byref(tken)):
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]
        class TP(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID),
                        ("Attributes", wt.DWORD)]
        tp = TP(); tp.PrivilegeCount = 1
        if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tp.Luid)):
            tp.Attributes = 2
            adv.AdjustTokenPrivileges(tken, False, ctypes.byref(tp), 0, None, None)
        k32.CloseHandle(tken)
except Exception as e:
    log("sedebug failed: %r" % e)

# ---- 1. find game process -------------------------------------------
WANT = ("CreativeGrowtopia.exe", "Growtopia.exe")
pid = 0
pids = (wt.DWORD * 4096)()
need = wt.DWORD()
if not psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(need)):
    raise OSError("EnumProcesses failed")
npid = need.value // ctypes.sizeof(wt.DWORD)
found = []
for p in pids[:npid]:
    if not p:
        continue
    h = k32.OpenProcess(0x1010, False, p)  # QUERY_LIMITED|VM_READ
    if not h:
        continue
    exe = ctypes.create_unicode_buffer(260)
    psapi.GetModuleBaseNameW(h, None, exe, 260)
    if exe.value in WANT and (TARGET_EXE is None or exe.value.lower() == TARGET_EXE.lower()):
        found.append((p, exe.value))
    k32.CloseHandle(h)
if not found:
    raise RuntimeError("no game process running (%s)" % ", ".join(WANT))
pid, exe = found[0]
log("game: pid=%d exe=%s" % (pid, exe))

# QUERY_INFORMATION|CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ|QUERY_LIMITED
# CREATE_THREAD+VM_WRITE are mandatory for CreateRemoteThread / WPM
RIGHTS = 0x0010 | 0x0002 | 0x0020 | 0x2000 | 0x0008 | 0x1000
h = k32.OpenProcess(RIGHTS, False, pid)
if not h:
    raise OSError(ctypes.get_last_error(), "OpenProcess full rights failed")

def enum_modules(h):
    arr = (ctypes.c_void_p * 512)()
    need2 = wt.DWORD()
    out = {}
    if psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr),
                                  ctypes.byref(need2), 0x03):
        cnt = need2.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(cnt):
            nm = ctypes.create_unicode_buffer(260)
            psapi.GetModuleFileNameExW(h, ctypes.c_void_p(arr[i]), nm, 260)
            out[nm.value.split("\\")[-1].lower()] = arr[i]
    return out

def parse_exports(img):
    e = struct.unpack_from("<I", img, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", img, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    erva, _ = struct.unpack_from("<II", img, dd)
    if not erva:
        return {}
    def r2o(rva):
        return rva if 0 <= rva and rva + 8 <= len(img) else None
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
        ordd = struct.unpack_from("<H", img, r2o(ords_) + i * 2)[0]
        frva = struct.unpack_from("<I", img, r2o(funcs) + ordd * 4)[0]
        out[nm] = frva
    return out

def read_image(h, base):
    hdr = ctypes.create_string_buffer(0x400)
    n = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), hdr, 0x400, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "header read failed")
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    soi = struct.unpack_from("<I", hdr, e_lfanew + 80)[0]
    buf = ctypes.create_string_buffer(soi)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, soi, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "image read failed")
    return bytes(buf.raw[:n.value]), soi

# ---- 2. inject if needed --------------------------------------------
def epshax_key(m):
    # accepts EpsHax.dll / EpsHax2.dll — any freshly built variant
    return next((k for k in m if k.startswith("epshax") and k.endswith(".dll")), None)

mods = enum_modules(h)
key = epshax_key(mods)
if not key:
    log("EpsHax.dll not loaded — injecting %s" % DLL_PATH)
    dll_bytes = DLL_PATH.encode("utf-8") + b"\x00"
    addr = k32.VirtualAllocEx(h, None, len(dll_bytes), 0x3000, 0x04)  # COMMIT|RESERVE, RW
    if not addr:
        raise OSError(ctypes.get_last_error(), "VirtualAllocEx failed")
    wr = ctypes.c_size_t()
    if not k32.WriteProcessMemory(h, ctypes.c_void_p(addr), dll_bytes,
                                  len(dll_bytes), ctypes.byref(wr)):
        raise OSError(ctypes.get_last_error(), "WriteProcessMemory(dllpath) failed")
    hl = k32.GetModuleHandleW("kernel32.dll")
    loadlib = k32.GetProcAddress(hl, b"LoadLibraryA")
    if not loadlib:
        raise OSError("LoadLibraryA not found")
    ht = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(loadlib),
                                ctypes.c_void_p(addr), 0, None)
    if not ht:
        raise OSError(ctypes.get_last_error(), "CreateRemoteThread(LoadLibraryA) failed")
    rc = k32.WaitForSingleObject(ht, 20000)
    code = wt.DWORD()
    k32.GetExitCodeThread(ht, ctypes.byref(code))
    k32.CloseHandle(ht)
    log("LoadLibrary wait rc=%d module=0x%X" % (rc, code.value))
    if not code.value:
        raise RuntimeError("LoadLibraryA returned NULL — injection failed")
    time.sleep(4.0)   # let first frame run: ImGui init, g_executor creation
    mods = enum_modules(h)
    key = epshax_key(mods)
    if not key:
        raise RuntimeError("EpsHax.dll still not in module list")
else:
    log("EpsHax.dll already loaded @0x%X" % mods[key])

base = mods[key]
img, soi = read_image(h, base)
exports = parse_exports(img)
if "EpsHax_GetScriptBuf" not in exports:
    raise RuntimeError("old DLL: EpsHax_GetScriptBuf missing")
if "EpsHax_ExecuteScriptBuf" not in exports:
    raise RuntimeError("old DLL without EpsHax_ExecuteScriptBuf — rebuild/reinject required")

# scriptBuf address from getter thunk (lea rax,[rip+d])
frva = exports["EpsHax_GetScriptBuf"]
code = img[frva:frva + 16]
hops = 0
while len(code) >= 5 and code[0] == 0xE9 and hops < 8:
    frva = frva + 5 + struct.unpack_from("<i", code, 1)[0]
    code = img[frva:frva + 16]
    hops += 1
p = code.find(b"\x48\x8d\x05")
if p < 0:
    raise RuntimeError("cannot resolve scriptBuf, code=%s" % code[:12].hex())
disp = struct.unpack_from("<i", code, p + 3)[0]
buf_rva = frva + p + 7 + disp
if not (0 <= buf_rva and buf_rva + 262144 <= soi):
    raise RuntimeError("scriptBuf rva out of range 0x%X" % buf_rva)
script_addr = base + buf_rva
exec_addr = base + exports["EpsHax_ExecuteScriptBuf"]
log("scriptBuf @0x%X exec @0x%X" % (script_addr, exec_addr))

# ---- 3. write script -------------------------------------------------
with open(NEW_PATH, "rb") as f:
    new_bytes = f.read()
if len(new_bytes) >= 262144:
    raise RuntimeError("script too big %d" % len(new_bytes))
out = new_bytes + b"\x00"
wr = ctypes.c_size_t()
if not k32.WriteProcessMemory(h, ctypes.c_void_p(script_addr), out, len(out),
                              ctypes.byref(wr)):
    raise OSError(ctypes.get_last_error(), "WriteProcessMemory(script) failed")
log("wrote %d bytes" % wr.value)
n = ctypes.c_size_t()
chk = ctypes.create_string_buffer(len(out))
if not k32.ReadProcessMemory(h, ctypes.c_void_p(script_addr), chk, len(out),
                             ctypes.byref(n)):
    raise OSError(ctypes.get_last_error(), "readback failed")
assert bytes(chk.raw[:n.value]).startswith(new_bytes.split(b"\n")[0]), "readback mismatch"

# ---- 4. execute ------------------------------------------------------
ht = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(exec_addr), None, 0, None)
if not ht:
    raise OSError(ctypes.get_last_error(), "CreateRemoteThread(execute) failed")
rc = k32.WaitForSingleObject(ht, 15000)
log("execute thread wait rc=%d (0=done)" % rc)
k32.CloseHandle(ht)
k32.CloseHandle(h)
log("INJECT_POKE_OK")
