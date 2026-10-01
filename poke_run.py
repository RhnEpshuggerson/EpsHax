"""Poke a script into EpsHax's scriptBuf and execute it headlessly.

Finds the process with EpsHax.dll loaded, resolves two exports:
  EpsHax_GetScriptBuf      -> buffer address (write file contents there)
  EpsHax_ExecuteScriptBuf  -> remote thread entry (runs the buffer)
No game UI interaction needed. Must run elevated (game is elevated).

  python poke_run.py <script-path>
Exit code 0 = poked + remote thread started.
"""
import ctypes, ctypes.wintypes as wt, struct, sys, time

OUT_PATH = (r"C:\Users\LENOVO\Documents\groetopia\cv dl script\coems_executor"
            r"\package-scanner-output\poke_result.txt")

def _write_out(text):
    try:
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass

if len(sys.argv) < 2:
    print("usage: poke_run.py <script-path>", flush=True)
    sys.exit(2)
NEW_PATH = sys.argv[1]

# ---- self-elevation (game runs elevated) ----
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
        open(OUT_PATH, "w", encoding="utf-8").close()
    except Exception:
        pass
    se = ctypes.windll.shell32.ShellExecuteW
    se.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR,
                   wt.LPCWSTR, ctypes.c_int]
    se.restype = wt.HINSTANCE if hasattr(wt, "HINSTANCE") else ctypes.c_void_p
    rc = se(None, "runas", sys.executable, '"%s" "%s"' % (__file__, NEW_PATH), None, 1)
    line = "ShellExecuteW runas rc=%d" % rc
    print(line, flush=True)
    _write_out(line)
    sys.exit(0 if rc > 32 else 1)

def log(msg):
    print(msg, flush=True)
    _write_out(msg)

try:
    open(OUT_PATH, "w", encoding="utf-8").close()
except Exception:
    pass

def parse_exports(img):
    e = struct.unpack_from("<I", img, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", img, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    erva, esz = struct.unpack_from("<II", img, dd)
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
        ord_i = struct.unpack_from("<H", img, r2o(ords_) + i * 2)[0]
        frva = struct.unpack_from("<I", img, r2o(funcs) + ord_i * 4)[0]
        out[nm] = frva
    return out

def resolve_code_rva(img, frva, hops_max=8):
    code = img[frva:frva + 16]
    hops = 0
    while len(code) >= 5 and code[0] == 0xE9 and hops < hops_max:
        frva = frva + 5 + struct.unpack_from("<i", code, 1)[0]
        code = img[frva:frva + 16]
        hops += 1
    return frva

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p

# SeDebugPrivilege
try:
    tken = ctypes.c_void_p()
    if adv.OpenProcessToken(ctypes.c_void_p(-1), 0x0020 | 0x0008, ctypes.byref(tken)):
        tp = TOKEN_PRIVILEGES = None
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]
        class _TP(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wt.DWORD), ("Luid", LUID),
                        ("Attributes", wt.DWORD)]
        tpp = _TP(); tpp.PrivilegeCount = 1
        if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tpp.Luid)):
            tpp.Attributes = 2
            adv.AdjustTokenPrivileges(tken, False, ctypes.byref(tpp), 0, None, None)
    k32.CloseHandle(tken)
except Exception as e:
    log("sedebug failed: %r" % e)

# 1. find process with EpsHax.dll
ENUM_RIGHTS = 0x0010 | 0x1000
candidates = []
pids = (wt.DWORD * 4096)()
need = wt.DWORD()
if not psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(need)):
    raise OSError(ctypes.get_last_error(), "EnumProcesses failed")
npid = need.value // ctypes.sizeof(wt.DWORD)
for pid in pids[:npid]:
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
if not candidates:
    raise RuntimeError("no process has EpsHax.dll loaded (inject first)")
candidates.sort(key=lambda c: ("growtopia" not in c[2].lower() and
                               "creative" not in c[2].lower(), c[2]))
PID, target, pname = candidates[0]
log("target: pid=%d exe=%s base=0x%X" % (PID, pname, target))

RIGHTS = 0x0010 | 0x0020 | 0x0008 | 0x0400
h = k32.OpenProcess(RIGHTS, False, PID)
if not h:
    raise OSError(ctypes.get_last_error(), "OpenProcess failed")

# 2. read module image
hdr = ctypes.create_string_buffer(0x400)
n = ctypes.c_size_t()
if not k32.ReadProcessMemory(h, ctypes.c_void_p(target), hdr, 0x400, ctypes.byref(n)):
    raise OSError(ctypes.get_last_error(), "header read failed")
e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
size_of_image = struct.unpack_from("<I", hdr, e_lfanew + 80)[0]
img_buf = ctypes.create_string_buffer(size_of_image)
if not k32.ReadProcessMemory(h, ctypes.c_void_p(target), img_buf, size_of_image,
                             ctypes.byref(n)):
    raise OSError(ctypes.get_last_error(), "image read failed")
data = bytes(img_buf.raw[:n.value])

exports = parse_exports(data)
if "EpsHax_GetScriptBuf" not in exports:
    raise RuntimeError("EpsHax_GetScriptBuf export missing (old DLL?)")
if "EpsHax_ExecuteScriptBuf" not in exports:
    raise RuntimeError("EpsHax_ExecuteScriptBuf export missing (rebuild DLL)")

# buffer addr: lea rax,[rip+disp] inside the getter thunk
frva = resolve_code_rva(data, exports["EpsHax_GetScriptBuf"])
code = data[frva:frva + 16]
p = code.find(b"\x48\x8d\x05")
if p < 0:
    raise RuntimeError("cannot resolve scriptBuf: code=%s" % code[:12].hex())
disp = struct.unpack_from("<i", code, p + 3)[0]
buf_rva = frva + p + 7 + disp
if not (0 <= buf_rva and buf_rva + 262144 <= size_of_image):
    raise RuntimeError("scriptBuf rva out of range: 0x%X" % buf_rva)
script_addr = target + buf_rva
exec_addr = target + exports["EpsHax_ExecuteScriptBuf"]
log("scriptBuf @0x%X (rva 0x%X), exec @0x%X" % (script_addr, buf_rva, exec_addr))

# 3. write script
with open(NEW_PATH, "rb") as f:
    new_bytes = f.read()
if len(new_bytes) >= 262144:
    raise RuntimeError("script too big (%d)" % len(new_bytes))
out = new_bytes + b"\x00"
wr = ctypes.c_size_t()
if not k32.WriteProcessMemory(h, ctypes.c_void_p(script_addr), out, len(out),
                              ctypes.byref(wr)):
    raise OSError(ctypes.get_last_error(), "WriteProcessMemory failed")
log("wrote %d bytes" % wr.value)

chk = ctypes.create_string_buffer(len(out))
if not k32.ReadProcessMemory(h, ctypes.c_void_p(script_addr), chk, len(out),
                             ctypes.byref(n)):
    raise OSError(ctypes.get_last_error(), "readback failed")
rb = bytes(chk.raw[:n.value])
sig = new_bytes.split(b"\n")[0].rstrip(b"\r")
assert rb.startswith(sig), "readback line1 mismatch"

# 4. remote thread -> EpsHax_ExecuteScriptBuf()
THREAD_QUERY = 0x0008
k32.CreateRemoteThread.restype = ctypes.c_void_p
ht = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(exec_addr),
                            None, 0, None)
if not ht:
    raise OSError(ctypes.get_last_error(), "CreateRemoteThread failed")
log("remote thread started, waiting...")
rc = k32.WaitForSingleObject(ht, 15000)
log("WaitForSingleObject rc=%d (0=executed)" % rc)
k32.CloseHandle(ht)
k32.CloseHandle(h)
log("POKE_OK")
