#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "lua_api.h"
#include "hook.h"
#include "scanner.h"
#include "native_hook.h"
#include "discord_rpc.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <set>
#include <map>
#include <unordered_map>
#include <atomic>
#include <cstring>
#include <intrin.h>
#include <dbghelp.h>
#include "epshook.h"
#pragma comment(lib, "dbghelp.lib")

// Set to 1 to enable native hook (code patching). DISABLED by default because
// Themida/VMProtect anti-tamper in Growtopia detects E9 JMP patches at game
// code addresses and crashes the process (ACCESS_VIOLATION at 0xD17DFFF5).
// The BCrypt/TLS/socket hooks already capture all packet data without patching
// game code, so the native hook is not needed for normal operation.
#define ENABLE_NATIVE_HOOK 1

float g_currentTime = 0;

// When true, suppress VEH crash logging (scanners hit unmapped memory intentionally)
volatile LONG g_ScanningActive = 0;
// Set while scanner::SafeReadBytes probes possibly-unreadable addresses
volatile LONG g_SafeReadProbe = 0;

// Heap scanning runs on a worker thread — game threads only post a rate-limited request
static volatile LONG g_HeapScanRequest = 0;
static DWORD g_LastHeapScanReq = 0;

static void RequestHeapScan() {
    DWORD now = GetTickCount();
    if (now - g_LastHeapScanReq >= 400) {
        g_LastHeapScanReq = now;
        InterlockedExchange(&g_HeapScanRequest, 1);
    }
}

// ── Heap scanner for decrypted packet data ─────────────────────────
// OFF (user directive: the 366-region scan burns ~49% CPU — fan noise).
// Re-enable only after the scanner is rewritten to be cheap.
static bool g_HeapScanEnabled = false;
static int g_HeapScanHits = 0;
static uintptr_t g_LastScanRegion = 0;

static bool IsHeapReadable(uintptr_t addr, size_t len) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (len > mbi.RegionSize) return false;
    DWORD bad = PAGE_NOACCESS | PAGE_GUARD | PAGE_EXECUTE | PAGE_EXECUTE_READ;
    return (mbi.Protect & bad) == 0 && (mbi.Protect != 0);
}

static bool IsAsciiPrintable(unsigned char c) {
    return (c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t';
}

static bool SafeMemCmp(const BYTE* a, const BYTE* b, size_t len) {
    __try {
        return memcmp(a, b, len) == 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static int SafeAsciiLen(const BYTE* base, size_t maxSize) {
    int len = 0;
    __try {
        while (len < 512 && (size_t)len < maxSize) {
            unsigned char c = base[len];
            if (c == 0) break;
            if (!IsAsciiPrintable(c) && c != '\n' && c != '\r') return 0;
            len++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return len;
}

// Extract a single packet from memory: reads until double newline or null
extern "C" {
    static const BYTE* s_extractBase = nullptr;
    static size_t s_extractMax = 0;
    static char s_extractBuf[512];
    static int s_extractLen = 0;

    static void __cdecl DoExtractPacket() {
        s_extractLen = 0;
        size_t maxLen = (s_extractMax < 511) ? s_extractMax : 511;
        size_t i = 0;
        int newlines = 0;
        while (i < maxLen) {
            unsigned char c = s_extractBase[i];
            if (c == 0) break;
            if (c == '\n') {
                newlines++;
                if (newlines >= 2) break;
            } else {
                newlines = 0;
            }
            if (!IsAsciiPrintable(c) && c != '\n' && c != '\r') break;
            s_extractBuf[s_extractLen++] = (char)c;
            i++;
        }
        if (s_extractLen >= 0 && s_extractLen < 512)
            s_extractBuf[s_extractLen] = '\0';
        else if (s_extractLen >= 512)
            s_extractBuf[511] = '\0';
    }

    static int __cdecl TryExtractPacket(const BYTE* base, size_t maxSize) {
        s_extractBase = base;
        s_extractMax = maxSize;
        s_extractLen = 0;
        s_extractBuf[0] = '\0';
        __try {
            DoExtractPacket();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s_extractLen = 0;
            s_extractBuf[0] = '\0';
        }
        return s_extractLen;
    }
}

static std::string SafeExtractPacket(const BYTE* base, size_t maxSize) {
    int len = TryExtractPacket(base, maxSize);
    return std::string(s_extractBuf, len);
}

void ScanHeapForPackets() {
    if (!g_HeapScanEnabled) return;

    {
        static int s_enter = 0;
        s_enter++;
        if (s_enter <= 5 || s_enter % 10 == 0) {
            char m[96];
            snprintf(m, sizeof(m), "[HEAPSCAN] enter #%d", s_enter);
            consoleLog(m);
        }
    }

    InterlockedExchange(&g_ScanningActive, 1);

    const char* markers[] = {
        "action|spawn",
        "action|on_spawn",
        "on_varlist",
        "set_field_init",
        "set_field_update",
        "on_requestWorldSelectMenu",
        "on_chat_message",
        "on_killed",
        "on_disconnect",
        "play_sfx",
        "tankIDName",
        "action|",
        "set_field",
    };
    const int markerCount = sizeof(markers) / sizeof(markers[0]);

    static std::vector<std::string> recentPackets;

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi = {};
    int regionsScanned = 0;
    size_t bytesScanned = 0;

    while (addr < 0x7FFFFFFFFFFFFFFF && regionsScanned < 500 && bytesScanned < 48 * 1024 * 1024) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 64 && mbi.RegionSize < 0x8000000) {
            DWORD prot = mbi.Protect;
            // Skip executable regions — text packets are in heap (RW) memory
            bool isExec = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool noAccess = (prot & (PAGE_NOACCESS | PAGE_GUARD)) != 0;
            bool isReadable = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            if (isReadable && !isExec && !noAccess) {
                BYTE* base = (BYTE*)mbi.BaseAddress;
                size_t size = mbi.RegionSize;

                for (int m = 0; m < markerCount; m++) {
                    size_t markerLen = strlen(markers[m]);
                    if (markerLen + 20 >= size) continue;

                    for (size_t i = 0; i + markerLen + 10 < size; i++) {
                        if (!SafeMemCmp(base + i, (const BYTE*)markers[m], markerLen)) continue;

                        std::string text = SafeExtractPacket(base + i, size - i);
                        if (text.size() > markerLen + 5) {
                            size_t firstLineEnd = text.find('\n');
                            if (firstLineEnd != std::string::npos && firstLineEnd > 2) {
                                std::string firstLine = text.substr(0, firstLineEnd);
                                size_t pipe = firstLine.find('|');
                                if (pipe != std::string::npos) {
                                    std::string key = firstLine.substr(0, pipe);
                                    bool valid = true; // Found by specific marker, accept it
                                    if (valid) {
                                        std::string preview = text.substr(0, 80);
                                        bool dup = false;
                                        for (auto& r : recentPackets) { if (r == preview) { dup = true; break; } }
                                        if (!dup) {
                                            recentPackets.push_back(preview);
                                            if (recentPackets.size() > 100) recentPackets.erase(recentPackets.begin());
                                            g_HeapScanHits++;
                                            // Event feed DISABLED: TJ spy now delivers
                                            // genuine packets — heap scan matched lua
                                            // string-pool fragments (script source with
                                            // embedded "action|..." / "OnDialogRequest")
                                            // and fed them as real inbound events.
                                            consoleLog("[HEAPSCAN #" + std::to_string(g_HeapScanHits) + "] " + text.substr(0, 120));
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
            regionsScanned++;
            bytesScanned += mbi.RegionSize;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr <= (uintptr_t)mbi.BaseAddress) break;
    }

    {
        static int s_runs = 0;
        s_runs++;
        if (s_runs % 10 == 1) {
            char m[96];
            snprintf(m, sizeof(m), "[HEAPSCAN] run#%d regions=%d hits=%d",
                     s_runs, regionsScanned, g_HeapScanHits);
            consoleLog(m);
        }
    }

    InterlockedExchange(&g_ScanningActive, 0);
}

// Pure-C crash writer (no C++ objects in scope so __try works)
// Called from VehHandler with copied context so nested exceptions are safe
static void WriteHookState(HANDLE hFile);
static void WriteCrashLog(DWORD excCode, void* excAddr, DWORD_PTR accessType, DWORD_PTR accessAddr, CONTEXT* ctx) {
    const char* dir = "C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\package-scanner-output\\Crash log";
    CreateDirectoryA(dir, nullptr);

    char path[MAX_PATH];
    int idx = 0;
    for (;;) {
        if (idx == 0)
            snprintf(path, sizeof(path), "%s\\crash.txt", dir);
        else
            snprintf(path, sizeof(path), "%s\\crash%d.txt", dir, idx);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(path, &fd);
        if (hFind == INVALID_HANDLE_VALUE) break;
        FindClose(hFind);
        idx++;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD written;
    char buf[512];

    const char* excName = "UNKNOWN";
    if (excCode == EXCEPTION_ACCESS_VIOLATION) excName = "ACCESS_VIOLATION";
    else if (excCode == EXCEPTION_STACK_OVERFLOW) excName = "STACK_OVERFLOW";
    else if (excCode == EXCEPTION_ILLEGAL_INSTRUCTION) excName = "ILLEGAL_INSTRUCTION";
    else if (excCode == 0xC0000374) excName = "HEAP_CORRUPTION";
    else if (excCode == 0xC0000409) excName = "FAIL_FAST";

    int n = snprintf(buf, sizeof(buf),
        "=== CRASH LOG ===\r\n"
        "Exception: %s (0x%08X)\r\n"
        "Address: 0x%p\r\n"
        "Access type: %s\r\n"
        "Access address: 0x%p\r\n\r\n"
        "=== REGISTERS ===\r\n",
        excName, excCode, excAddr,
        accessType ? "WRITE" : "READ",
        (void*)accessAddr);
    WriteFile(hFile, buf, n, &written, nullptr);

#ifdef _WIN64
    n = snprintf(buf, sizeof(buf),
        "RAX=0x%016llX  RBX=0x%016llX\r\n"
        "RCX=0x%016llX  RDX=0x%016llX\r\n"
        "RSI=0x%016llX  RDI=0x%016llX\r\n"
        "RSP=0x%016llX  RBP=0x%016llX\r\n"
        "R8 =0x%016llX  R9 =0x%016llX\r\n"
        "R10=0x%016llX  R11=0x%016llX\r\n"
        "R12=0x%016llX  R13=0x%016llX\r\n"
        "R14=0x%016llX  R15=0x%016llX\r\n"
        "RIP=0x%016llX  EFLAGS=0x%08X\r\n\r\n",
        ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx,
        ctx->Rsi, ctx->Rdi, ctx->Rsp, ctx->Rbp,
        ctx->R8, ctx->R9, ctx->R10, ctx->R11,
        ctx->R12, ctx->R13, ctx->R14, ctx->R15,
        ctx->Rip, ctx->EFlags);
    WriteFile(hFile, buf, n, &written, nullptr);

    // Dump bytes around faulting instruction — wrapped in __try because the
    // address may be completely unmapped (anti-tamper redirect, etc.)
    {
        BYTE* rip = (BYTE*)ctx->Rip;
        n = snprintf(buf, sizeof(buf), "=== CODE AROUND RIP ===\r\n");
        WriteFile(hFile, buf, n, &written, nullptr);
        for (int i = -16; i < 32; i++) {
            BYTE* p = rip + i;
            BYTE val = 0;
            __try {
                val = *p;
                n = (i == 0)
                    ? snprintf(buf, sizeof(buf), ">>> %02X ", val)
                    : snprintf(buf, sizeof(buf), "    %02X ", val);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                n = snprintf(buf, sizeof(buf), "    ?? ");
            }
            WriteFile(hFile, buf, n, &written, nullptr);
            if ((i + 1) % 8 == 0) WriteFile(hFile, "\r\n", 2, &written, nullptr);
        }
    }
#else
    n = snprintf(buf, sizeof(buf),
        "EAX=0x%08X  EBX=0x%08X\r\n"
        "ECX=0x%08X  EDX=0x%08X\r\n"
        "ESI=0x%08X  EDI=0x%08X\r\n"
        "ESP=0x%08X  EBP=0x%08X\r\n"
        "EIP=0x%08X  EFLAGS=0x%08X\r\n\r\n",
        ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx,
        ctx->Esi, ctx->Edi, ctx->Esp, ctx->Ebp,
        ctx->Eip, ctx->EFlags);
    WriteFile(hFile, buf, n, &written, nullptr);
#endif

    // Dump stack (512 bytes)
    n = snprintf(buf, sizeof(buf), "\r\n=== STACK (512 bytes) ===\r\n");
    WriteFile(hFile, buf, n, &written, nullptr);
#ifdef _WIN64
    uintptr_t* sp = (uintptr_t*)ctx->Rsp;
#else
    uintptr_t* sp = (uintptr_t*)ctx->Esp;
#endif
    for (int i = 0; i < 64; i++) {
        uintptr_t val = 0;
        __try {
            val = sp[i];
            n = snprintf(buf, sizeof(buf), "  [RSP+0x%03X] 0x%p\r\n", i * 8, (void*)val);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            n = snprintf(buf, sizeof(buf), "  [RSP+0x%03X] <unreadable>\r\n", i * 8);
        }
        WriteFile(hFile, buf, n, &written, nullptr);
    }

    // Resolved call-stack frames (walks through VEH into faulting frames)
    n = snprintf(buf, sizeof(buf), "\r\n=== STACK FRAMES (resolved) ===\r\n");
    WriteFile(hFile, buf, n, &written, nullptr);
    {
        void* frames[48] = {};
        USHORT nFrames = CaptureStackBackTrace(0, 48, frames, nullptr);
        for (USHORT fi = 0; fi < nFrames; fi++) {
            char modName[MAX_PATH] = "<nomodule>";
            ptrdiff_t rva = 0;
            __try {
                HMODULE hm = nullptr;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       (LPCSTR)frames[fi], &hm) && hm) {
                    char path[MAX_PATH] = {};
                    if (GetModuleFileNameA(hm, path, MAX_PATH)) {
                        const char* base = strrchr(path, '\\');
                        base = base ? base + 1 : path;
                        strncpy_s(modName, base, _TRUNCATE);
                    }
                    rva = (const char*)frames[fi] - (const char*)hm;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            n = snprintf(buf, sizeof(buf), "  #%02d 0x%p  %s+0x%llX\r\n",
                         fi, frames[fi], modName, (unsigned long long)rva);
            WriteFile(hFile, buf, n, &written, nullptr);
        }
    }

    // Raw scan of faulting stack for pointers into loaded modules —
    // catches return addresses when unwind chains are broken by corruption
    n = snprintf(buf, sizeof(buf), "\r\n=== RAW STACK SCAN (module pointers, [RSP..RSP+0x800]) ===\r\n");
    WriteFile(hFile, buf, n, &written, nullptr);
    {
        struct Mod { HMODULE h; const char* name; };
        Mod mods[8] = {};
        int nMods = 0;
        const char* wanted[] = { "EpsHax.dll", "Growtopia.exe", "ntdll.dll",
                                 "kernelbase.dll", "ws2_32.dll", "kernel32.dll" };
        for (int w = 0; w < 6; w++) {
            HMODULE hm = GetModuleHandleA(wanted[w]);
            if (hm) mods[nMods++] = { hm, wanted[w] };
        }
        for (int i = 0; i < 256; i++) {   // 256 qwords = 0x800 bytes
            uintptr_t val = 0;
            __try { val = sp[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            for (int m = 0; m < nMods; m++) {
                if (val >= (uintptr_t)mods[m].h &&
                    val <  (uintptr_t)mods[m].h + 0x800000) {
                    n = snprintf(buf, sizeof(buf), "  [RSP+0x%03X] 0x%p  %s+0x%llX\r\n",
                                 i * 8, (void*)val, mods[m].name,
                                 (unsigned long long)(val - (uintptr_t)mods[m].h));
                    WriteFile(hFile, buf, n, &written, nullptr);
                    break;
                }
            }
        }
    }

    // Dump game function addresses
    n = snprintf(buf, sizeof(buf),
        "\r\n=== RESOLVED ADDRESSES ===\r\n"
        "ProcessTankUpdatePacket = 0x%p\r\n"
        "SendPacket = 0x%p\r\n"
        "GetGameLogic = 0x%p\r\n",
        (void*)scanner::fn_ProcessTankUpdatePacket,
        (void*)scanner::fn_SendPacket,
        (void*)scanner::fn_GetGameLogic);
    WriteFile(hFile, buf, n, &written, nullptr);

    WriteHookState(hFile);

    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    // Best-effort minidump next to the text log (same base name .dmp).
    // Small dump type keeps overnight crash loops from filling the disk.
    {
        char dumpPath[MAX_PATH];
        strncpy_s(dumpPath, path, _TRUNCATE);
        char* dot = strstr(dumpPath, ".txt");
        if (dot) strcpy_s(dot, sizeof(dumpPath) - (dot - dumpPath), ".dmp");
        HANDLE hDump = CreateFileA(dumpPath, GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDump != INVALID_HANDLE_VALUE) {
            MINIDUMP_TYPE mt = (MINIDUMP_TYPE)(MiniDumpNormal | MiniDumpWithThreadInfo);
            MiniDumpWriteDump(GetCurrentProcess(), GetCurrentThreadId(), hDump,
                              mt, nullptr, nullptr, nullptr);
            CloseHandle(hDump);
        }
    }
}

// Unhandled-exception fallback: VehHandler covers first-chance fatal codes,
// this catches anything else that reaches the top (and fail-fast variants
// that skip user VEH). Same text + minidump output.
static LONG WINAPI UnhandledFilter(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_EXECUTE_HANDLER;
    if (g_ScanningActive) return EXCEPTION_EXECUTE_HANDLER;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    DWORD_PTR at = 0, aa = 0;
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        at = ep->ExceptionRecord->ExceptionInformation[0];
        aa = ep->ExceptionRecord->ExceptionInformation[1];
    }
    WriteCrashLog(code, (void*)ep->ExceptionRecord->ExceptionAddress,
                  at, aa, ep->ContextRecord);
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG WINAPI VehHandler(EXCEPTION_POINTERS* ep) {
    DWORD ec = ep->ExceptionRecord->ExceptionCode;
    if (ec == EXCEPTION_ACCESS_VIOLATION ||
        ec == EXCEPTION_STACK_OVERFLOW ||
        ec == EXCEPTION_ILLEGAL_INSTRUCTION ||
        ec == 0xC0000374 ||   // STATUS_HEAP_CORRUPTION
        ec == 0xC0000409) {   // STATUS_FAIL_FAST_EXCEPTION (__fastfail)

        // Suppress crash logs during memory scans — scanners intentionally hit unmapped memory
        if (InterlockedCompareExchange(&g_ScanningActive, 0, 0) != 0 ||
            InterlockedCompareExchange(&g_SafeReadProbe, 0, 0) != 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Rate-limit crash logs to at most 1 per 5 seconds
        static DWORD lastCrashLogTime = 0;
        DWORD now = GetTickCount();
        if (now - lastCrashLogTime < 5000) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        lastCrashLogTime = now;

        // Prevent nested VEH calls (our handler crashing triggers another exception)
        static LONG g_inVeh = 0;
        if (InterlockedCompareExchange(&g_inVeh, 1, 0) != 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Extract exception info and copy context before calling C function
        DWORD excCode = ep->ExceptionRecord->ExceptionCode;
        void* excAddr = ep->ExceptionRecord->ExceptionAddress;
        DWORD_PTR accessType = ep->ExceptionRecord->ExceptionInformation[0];
        DWORD_PTR accessAddr = ep->ExceptionRecord->ExceptionInformation[1];
        CONTEXT ctxCopy = {};
#ifdef _WIN64
        memcpy(&ctxCopy, ep->ContextRecord, sizeof(CONTEXT));
#else
        memcpy(&ctxCopy, ep->ContextRecord, sizeof(CONTEXT));
#endif

        WriteCrashLog(excCode, excAddr, accessType, accessAddr, &ctxCopy);

        InterlockedExchange(&g_inVeh, 0);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

extern void writeFileLog(const std::string& msg);

void debugLog(const std::string& msg) {
    {
        std::lock_guard<std::mutex> lock(g_debugMutex);
        g_debugLogs.push_back({msg, g_currentTime});
        if (g_debugLogs.size() > 1000) g_debugLogs.erase(g_debugLogs.begin());
    }
    writeFileLog(msg);
}

// ── send/recv/sendto/recvfrom hooks ──────────────────────────────────
typedef int (WINAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int (WINAPI* sendto_t)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
typedef int (WINAPI* recvfrom_t)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef int (WINAPI* WSASend_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* WSARecv_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* WSARecvFrom_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* from, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* WSASendTo_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* to, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
typedef SOCKET (WINAPI* WSASocketW_t)(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags);

// Diagnose-only guard: o_* should always be set after hook install. If a hook
// fires with a null original (corrupted global), log ONCE and bail instead of
// jumping to 0x0.
#define GUARD_ORIG(name, retval) \
    if (!o_##name) { \
        static volatile long s_##name##Null_ = 0; \
        if (InterlockedCompareExchange(&s_##name##Null_, 1, 0) == 0) \
            consoleLog(std::string("[FATAL] o_") + #name + " == NULL in hk_" #name); \
        WSASetLastError(WSAENOTSOCK); \
        return retval; \
    }

// Callers (WinHTTP/webio) fastfail the whole process if a winsock call returns
// SOCKET_ERROR while WSAGetLastError() == 0 — and our post-call logging (file
// I/O etc.) resets the thread's last-error to 0. Capture right after the
// original call, restore before returning.
#define SAVE_LAST_ERROR() DWORD _le = WSAGetLastError()
#define RESTORE_LAST_ERROR() WSASetLastError(_le)

send_t o_send = nullptr;
recv_t o_recv = nullptr;
sendto_t o_sendto = nullptr;
recvfrom_t o_recvfrom = nullptr;
WSASend_t o_WSASend = nullptr;
WSARecv_t o_WSARecv = nullptr;
WSARecvFrom_t o_WSARecvFrom = nullptr;
WSASendTo_t o_WSASendTo = nullptr;
connect_t o_connect = nullptr;
WSASocketW_t o_WSASocketW = nullptr;
SOCKET g_GameSocket = INVALID_SOCKET;

static int g_SendCount = 0;

static void LogHexDump(const char* tag, const void* data, int bytes) {
    const unsigned char* p = (const unsigned char*)data;
    char line[176];
    int shown = bytes > 256 ? 256 : bytes;
    snprintf(line, sizeof(line), "%s (%dB%s):", tag, bytes, bytes > shown ? " showing256" : "");
    consoleLog(line);
    for (int off = 0; off < shown; off += 32) {
        int pos = snprintf(line, sizeof(line), "  %04X:", off);
        int end = off + 32 < shown ? off + 32 : shown;
        for (int i = off; i < end && pos < 166; i++) {
            pos += snprintf(line + pos, 166 - pos, " %02X", p[i]);
        }
        consoleLog(line);
    }
}

static void LogStack(const char* tag) {
    void* frames[6] = {};
    USHORT n = CaptureStackBackTrace(0, 6, frames, NULL);
    char msg[320];
    int pos = snprintf(msg, sizeof(msg), "  [%s stack]", tag);
    for (USHORT i = 0; i < n && i < 6; i++) {
        pos += snprintf(msg + pos, sizeof(msg) - pos, " %p", frames[i]);
    }
    consoleLog(msg);
}

static void LogPeerOnce(SOCKET s) {
    static std::mutex m;
    static std::set<SOCKET> done;
    {
        std::lock_guard<std::mutex> lk(m);
        if (done.count(s)) return;
        done.insert(s);
    }
    sockaddr_in a = {};
    int l = sizeof(a);
    char ip[48] = "?";
    int port = 0;
    if (getpeername(s, (sockaddr*)&a, &l) == 0) {
        inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
        port = ntohs(a.sin_port);
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "[SOCKET %llu] peer=%s:%d",
             (unsigned long long)s, ip, port);
    consoleLog(msg);
}

// true for TLS record headers and TLS handshake/change-cipher message bodies
static bool LooksTls(const char* buf, int len) {
    if (len < 3) return true;
    unsigned char b0 = buf[0], b1 = buf[1], b2 = buf[2];
    if ((b0 >= 0x14 && b0 <= 0x17) && b1 == 0x03 && (b2 == 0x01 || b2 == 0x03 || b2 == 0x04)) return true;
    // TLS handshake body without record header: type(1) len(3) then version 03 03
    if (len >= 6 && b1 == 0x00 && b2 == 0x00 &&
        (b0 == 0x02 || b0 == 0x0B || b0 == 0x0C || b0 == 0x0E || b0 == 0x10 || b0 == 0x14)) return true;
    // change-cipher-spec body: 01 00 00 01
    if (len >= 4 && b0 == 0x01 && b1 == 0x00 && b2 == 0x00 && buf[3] == 0x01) return true;
    return false;
}

int WINAPI hk_send(SOCKET s, const char* buf, int len, int flags) {
    if (len > 4 && buf) {
        if (GameState::instance().interceptCommand(buf, len)) return len;
        if (!GameState::instance().parseOutgoing(buf, len)) {
            debugLog("[SEND] blocked by Lua hook len=" + std::to_string(len));
            return len;
        }
    }
    g_SendCount++;
    if (g_SendCount <= 200) {
        void* retAddr = _ReturnAddress();
        if (len >= 60 && buf) {
            char tag[80];
            snprintf(tag, sizeof(tag), "[SEND #%d] len=%d ret=0x%p", g_SendCount, len, retAddr);
            LogHexDump(tag, buf, len);
            LogStack("SEND");
        } else {
            char hex[128] = {};
            int pos = 0;
            for (int i = 0; i < 32 && i < len && pos < 120; i++) {
                pos += snprintf(hex + pos, 128 - pos, "%02X ", (unsigned char)buf[i]);
            }
            char buf2[512];
            snprintf(buf2, sizeof(buf2), "[SEND #%d] len=%d ret=0x%p %s",
                g_SendCount, len, retAddr, hex);
            consoleLog(buf2);
        }
    }
    GUARD_ORIG(send, SOCKET_ERROR)
    return o_send(s, buf, len, flags);
}

static int g_RecvCount = 0;
static int g_TlsAppDataCount = 0;

int WINAPI hk_recv(SOCKET s, char* buf, int len, int flags) {
    GUARD_ORIG(recv, SOCKET_ERROR)
    int result = o_recv(s, buf, len, flags);
    SAVE_LAST_ERROR();

    if (result > 4 && buf) {
        // Parse plaintext game packets directly (skip TLS records/messages)
        if (!LooksTls(buf, result)) {
            GameState::instance().parseIncoming(buf, result);
        }
        RequestHeapScan();
    }
    g_RecvCount++;
    if (result >= 5 && buf) {
        bool isTlsAppData = ((unsigned char)buf[0] == 0x17 &&
                             (unsigned char)buf[1] == 0x03 && (unsigned char)buf[2] == 0x03);
        if (isTlsAppData && g_TlsAppDataCount < 3) {
            g_TlsAppDataCount++;
            void* frames[64] = {};
            USHORT frameCount = CaptureStackBackTrace(0, 64, frames, NULL);
            char hex[256] = {};
            int pos = 0;
            for (int i = 0; i < 32 && i < result && pos < 240; i++) {
                pos += snprintf(hex + pos, 240 - pos, "%02X ", (unsigned char)buf[i]);
            }
            char msg[4096];
            int m = snprintf(msg, sizeof(msg),
                "[TLS-APPDATA #%d] len=%d frames=%d\n  DATA: %s\n  FRAMES:",
                g_TlsAppDataCount, result, frameCount, hex);
            for (USHORT i = 0; i < frameCount && m < 3900; i++) {
                m += snprintf(msg + m, 3900 - m, "\n  [%d] 0x%p", i, frames[i]);
                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQuery(frames[i], &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
                    unsigned char* bytes = (unsigned char*)frames[i];
                    m += snprintf(msg + m, 3900 - m, " bytes=");
                    for (int b = 0; b < 16 && m < 3900; b++) {
                        m += snprintf(msg + m, 3900 - m, "%02X ", bytes[b]);
                    }
                } else {
                    m += snprintf(msg + m, 3900 - m, " [unmapped]");
                }
            }
            consoleLog(msg);
        }
    }
    if (g_RecvCount <= 200 && result > 0) {
        void* retAddr = _ReturnAddress();
        if (result >= 60 && !LooksTls(buf, result)) {
            char tag[80];
            snprintf(tag, sizeof(tag), "[RECV #%d] len=%d ret=0x%p", g_RecvCount, result, retAddr);
            LogHexDump(tag, buf, result);
            LogStack("RECV");
        } else {
            char hex[128] = {};
            int pos = 0;
            for (int i = 0; i < 32 && i < result && pos < 120; i++) {
                pos += snprintf(hex + pos, 128 - pos, "%02X ", (unsigned char)buf[i]);
            }
            char buf2[512];
            snprintf(buf2, sizeof(buf2), "[RECV #%d] len=%d ret=0x%p %s",
                g_RecvCount, result, retAddr, hex);
            consoleLog(buf2);
        }
    }
    RESTORE_LAST_ERROR();
    return result;
}

static int g_SendToCount = 0;

int WINAPI hk_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    if (len > 4 && buf) {
        if (GameState::instance().interceptCommand(buf, len)) return len;
        if (!GameState::instance().parseOutgoing(buf, len)) {
            debugLog("[SENDTO] blocked by Lua hook len=" + std::to_string(len));
            return len;
        }
    }
    g_SendToCount++;
    if (g_SendToCount <= 60 && len > 0 && buf) {
        if (len >= 60) {
            char tag[64];
            snprintf(tag, sizeof(tag), "[SENDTO #%d]", g_SendToCount);
            LogHexDump(tag, buf, len);
            LogStack("SENDTO");
        } else {
            char hex[192] = {};
            int pos = 0;
            for (int i = 0; i < 48 && i < len && pos < 180; i++) {
                pos += snprintf(hex + pos, 192 - pos, "%02X ", (unsigned char)buf[i]);
            }
            char msg[288];
            snprintf(msg, sizeof(msg), "[SENDTO #%d] len=%d %s", g_SendToCount, len, hex);
            consoleLog(msg);
        }
    }
    GUARD_ORIG(sendto, SOCKET_ERROR)
    return o_sendto(s, buf, len, flags, to, tolen);
}

static int g_RecvFromCount = 0;

int WINAPI hk_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    GUARD_ORIG(recvfrom, SOCKET_ERROR)
    int result = o_recvfrom(s, buf, len, flags, from, fromlen);
    SAVE_LAST_ERROR();
    if (result > 4 && buf) {
        GameState::instance().parseIncoming(buf, result);
        RequestHeapScan();
    }
    g_RecvFromCount++;
    if (g_RecvFromCount <= 15 && result > 0) {
        char hex[192] = {};
        int pos = 0;
        for (int i = 0; i < 48 && i < result && pos < 180; i++) {
            pos += snprintf(hex + pos, 192 - pos, "%02X ", (unsigned char)buf[i]);
        }
        char msg[288];
        snprintf(msg, sizeof(msg), "[RECVFROM #%d] len=%d %s", g_RecvFromCount, result, hex);
        consoleLog(msg);
    }
    RESTORE_LAST_ERROR();
    return result;
}

static int g_WsaSendCount = 0;

int WINAPI hk_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (lpBuffers[i].len > 4 && lpBuffers[i].buf) {
            if (GameState::instance().interceptCommand(lpBuffers[i].buf, lpBuffers[i].len)) {
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = lpBuffers[i].len;
                return 0;
            }
            if (!GameState::instance().parseOutgoing(lpBuffers[i].buf, lpBuffers[i].len)) {
                debugLog("[WSASEND] blocked by Lua hook");
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = lpBuffers[i].len;
                return 0;
            }
        }
    }
    g_WsaSendCount++;
    if (g_WsaSendCount <= 100 && dwBufferCount > 0 && lpBuffers[0].buf && lpBuffers[0].len > 0) {
        LogPeerOnce(s);
        if (lpBuffers[0].len >= 8) {
            char tag[80];
            snprintf(tag, sizeof(tag), "[WSASEND #%d] s=%llu len=%d",
                     g_WsaSendCount, (unsigned long long)s, (int)lpBuffers[0].len);
            LogHexDump(tag, lpBuffers[0].buf, (int)lpBuffers[0].len);
            LogStack("WSASEND");
        }
    }
    GUARD_ORIG(WSASend, SOCKET_ERROR)
    return o_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

// parse WSA-style receive: non-overlapped success only, actual byte count
static void ParseWsaRecv(const char* tag, LPWSABUF lpBuffers, DWORD dwBufferCount, DWORD bytes) {
    if (!lpBuffers || bytes < 5) return;
    DWORD remaining = bytes;
    for (DWORD i = 0; i < dwBufferCount && remaining > 0; i++) {
        if (!lpBuffers[i].buf) break;
        DWORD n = lpBuffers[i].len < remaining ? lpBuffers[i].len : remaining;
        remaining -= n;
        if (n > 4 && !LooksTls(lpBuffers[i].buf, (int)n)) {
            GameState::instance().parseIncoming(lpBuffers[i].buf, (int)n);
            RequestHeapScan();
        }
    }
}

static int g_WsaRecvCount = 0;
static int g_LoopInCount = 0;

// overlapped WSARecv: buffer arrives later — remember (ol -> copied WSABUFs)
static std::mutex g_PendMx;
static std::unordered_map<LPOVERLAPPED, std::pair<std::vector<WSABUF>, SOCKET>> g_PendRecv;

static void OnRecvCompletion(LPOVERLAPPED ol, DWORD bytes) {
    std::vector<WSABUF> bufs;
    {
        std::lock_guard<std::mutex> lk(g_PendMx);
        auto it = g_PendRecv.find(ol);
        if (it == g_PendRecv.end()) return;
        bufs = std::move(it->second.first);
        g_PendRecv.erase(it);
    }
    if (bytes < 5 || bufs.empty()) return;

    DWORD remaining = bytes;
    for (auto& wb : bufs) {
        if (!wb.buf || remaining == 0) break;
        DWORD n = wb.len < remaining ? wb.len : remaining;
        remaining -= n;
        if (n > 4 && !LooksTls(wb.buf, (int)n)) {
            GameState::instance().parseIncoming(wb.buf, (int)n);
            RequestHeapScan();
        }
    }

    g_LoopInCount++;
    if (g_LoopInCount <= 80) {
        DWORD n0 = bytes < bufs[0].len ? bytes : bufs[0].len;
        char tag[80];
        snprintf(tag, sizeof(tag), "[LOOPIN #%d] bytes=%u", g_LoopInCount, bytes);
        LogHexDump(tag, bufs[0].buf, (int)n0);
        LogStack("LOOPIN");
    }
}

typedef BOOL (WINAPI* WSAGetOverlappedResult_t)(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpFlags);
typedef BOOL (WINAPI* GQCS_t)(HANDLE hCompletionPort, LPDWORD lpNumberOfBytesTransferred,
    PULONG_PTR lpCompletionKey, LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds);

WSAGetOverlappedResult_t o_WSAGetOverlappedResult = nullptr;
GQCS_t o_GetQueuedCompletionStatus = nullptr;

// Crash-time state of hook original pointers + hexdump of the .data page
// that holds them (RVA 0x360000, o_send@0x3608A0 o_recv@0x3608A8).
// Lets us see whether ONLY the pointers are zeroed or a whole range is.
static void WriteHookState(HANDLE hFile) {
    DWORD written;
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "\r\n=== HOOK ORIGINALS (nonzero = installed) ===\r\n"
        "o_send=0x%p o_recv=0x%p o_sendto=0x%p o_recvfrom=0x%p\r\n"
        "o_WSASend=0x%p o_WSARecv=0x%p o_WSARecvFrom=0x%p o_WSASendTo=0x%p\r\n"
        "o_connect=0x%p o_WSASocketW=0x%p\r\n"
        "o_WSAGetOverlappedResult=0x%p o_GetQueuedCompletionStatus=0x%p\r\n\r\n"
        "=== EpsHax .data page RVA 0x360000 ===\r\n",
        (void*)o_send, (void*)o_recv, (void*)o_sendto, (void*)o_recvfrom,
        (void*)o_WSASend, (void*)o_WSARecv, (void*)o_WSARecvFrom, (void*)o_WSASendTo,
        (void*)o_connect, (void*)o_WSASocketW,
        (void*)o_WSAGetOverlappedResult, (void*)o_GetQueuedCompletionStatus);
    WriteFile(hFile, buf, n, &written, nullptr);

    unsigned char* page = nullptr;
    HMODULE hm = GetModuleHandleA("EpsHax.dll");
    if (hm) page = (unsigned char*)hm + 0x360000;
    if (page) {
        for (int row = 0; row < 4096; row += 64) {
            int pos = snprintf(buf, sizeof(buf), "  +%03X:", row);
            for (int b = 0; b < 64 && pos < 480; b++) {
                unsigned char v = 0;
                __try { v = page[row + b]; } __except (EXCEPTION_EXECUTE_HANDLER) { v = 0; }
                pos += snprintf(buf + pos, sizeof(buf) - pos, " %02X", v);
            }
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\r\n");
            WriteFile(hFile, buf, pos, &written, nullptr);
        }
    }
}

// Pure-C safe copy of the .data page holding the o_* pointers (for watchdog)
static int ReadDataPageSafe(unsigned char* dst, int cap) {
    if (cap < 4096) return -1;
    HMODULE hm = GetModuleHandleA("EpsHax.dll");
    if (!hm) return -1;
    unsigned char* page = (unsigned char*)hm + 0x360000;
    for (int i = 0; i < 4096; i++) {
        __try { dst[i] = page[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { dst[i] = 0; }
    }
    return 4096;
}

int WINAPI hk_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    GUARD_ORIG(WSARecv, SOCKET_ERROR)
    int result = o_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
                           lpOverlapped, lpCompletionRoutine);
    SAVE_LAST_ERROR();
    g_WsaRecvCount++;

    if (lpOverlapped && !lpCompletionRoutine) {
        {
            std::lock_guard<std::mutex> lk(g_PendMx);
            g_PendRecv[lpOverlapped] = { std::vector<WSABUF>(lpBuffers, lpBuffers + dwBufferCount), s };
        }
        if (g_WsaRecvCount <= 40) {
            LogPeerOnce(s);
            char msg[160];
            snprintf(msg, sizeof(msg), "[WSARECV #%d] OVERLAPPED s=%llu bufs=%d result=%d ol=0x%p",
                     g_WsaRecvCount, (unsigned long long)s, (int)dwBufferCount, result, lpOverlapped);
            consoleLog(msg);
            LogStack("WSARECV-OL");
        }
        RESTORE_LAST_ERROR();
        return result;
    }

    if (result == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        DWORD bytes = *lpNumberOfBytesRecvd;
        ParseWsaRecv("WSARECV", lpBuffers, dwBufferCount, bytes);
        if (g_WsaRecvCount <= 60 && lpBuffers[0].buf) {
            LogPeerOnce(s);
            if (bytes >= 60 && !LooksTls(lpBuffers[0].buf, (int)bytes)) {
                char tag[80];
                snprintf(tag, sizeof(tag), "[WSARECV #%d] bytes=%d bufs=%d",
                         g_WsaRecvCount, (int)bytes, (int)dwBufferCount);
                LogHexDump(tag, lpBuffers[0].buf, (int)bytes);
                LogStack("WSARECV");
            } else {
                char hex[192] = {};
                int pos = 0;
                DWORD lim = bytes < 48 ? bytes : 48;
                for (DWORD i = 0; i < lim && pos < 180; i++) {
                    pos += snprintf(hex + pos, 192 - pos, "%02X ", (unsigned char)lpBuffers[0].buf[i]);
                }
                char msg[288];
                snprintf(msg, sizeof(msg), "[WSARECV #%d] bytes=%d bufs=%d %s",
                         g_WsaRecvCount, (int)bytes, (int)dwBufferCount, hex);
                 consoleLog(msg);
            }
        }
    } else if (g_WsaRecvCount <= 40) {
        char msg[144];
        snprintf(msg, sizeof(msg), "[WSARECV #%d] nonblock s=%llu result=%d ol=0x%p",
                 g_WsaRecvCount, (unsigned long long)s, result, lpOverlapped);
        consoleLog(msg);
    }
    RESTORE_LAST_ERROR();
    return result;
}

BOOL WINAPI hk_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpFlags) {
    BOOL r = o_WSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpFlags);
    SAVE_LAST_ERROR();
    if (r && lpOverlapped && lpcbTransfer) {
        OnRecvCompletion(lpOverlapped, *lpcbTransfer);
    }
    RESTORE_LAST_ERROR();
    return r;
}

BOOL WINAPI hk_GetQueuedCompletionStatus(HANDLE hCompletionPort,
    LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey,
    LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds) {
    BOOL r = o_GetQueuedCompletionStatus(hCompletionPort, lpNumberOfBytesTransferred,
                                         lpCompletionKey, lpOverlapped, dwMilliseconds);
    SAVE_LAST_ERROR();
    if (r && lpOverlapped && *lpOverlapped && lpNumberOfBytesTransferred) {
        OnRecvCompletion(*lpOverlapped, *lpNumberOfBytesTransferred);
    }
    RESTORE_LAST_ERROR();
    return r;
}

static int g_WsaRecvFromCount = 0;

int WINAPI hk_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* from, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    GUARD_ORIG(WSARecvFrom, SOCKET_ERROR)
    int result = o_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
                               from, lpFromlen, lpOverlapped, lpCompletionRoutine);
    SAVE_LAST_ERROR();
    if (!lpOverlapped && result == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        DWORD bytes = *lpNumberOfBytesRecvd;
        ParseWsaRecv("WSARECVFROM", lpBuffers, dwBufferCount, bytes);
        g_WsaRecvFromCount++;
        if (g_WsaRecvFromCount <= 80 && lpBuffers[0].buf) {
            if (bytes >= 60) {
                char tag[80];
                snprintf(tag, sizeof(tag), "[WSARECVFROM #%d] bytes=%d bufs=%d",
                         g_WsaRecvFromCount, (int)bytes, (int)dwBufferCount);
                LogHexDump(tag, lpBuffers[0].buf, (int)bytes);
                LogStack("RECVFROM");
            } else {
                char hex[192] = {};
                int pos = 0;
                DWORD lim = bytes < 48 ? bytes : 48;
                for (DWORD i = 0; i < lim && pos < 180; i++) {
                    pos += snprintf(hex + pos, 192 - pos, "%02X ", (unsigned char)lpBuffers[0].buf[i]);
                }
                char msg[288];
                snprintf(msg, sizeof(msg), "[WSARECVFROM #%d] bytes=%d bufs=%d %s",
                         g_WsaRecvFromCount, (int)bytes, (int)dwBufferCount, hex);
                consoleLog(msg);
            }
        }
    }
    RESTORE_LAST_ERROR();
    return result;
}

static int g_WsaSendToCount = 0;

int WINAPI hk_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* to, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (lpBuffers[i].len > 4 && lpBuffers[i].buf) {
            if (GameState::instance().interceptCommand(lpBuffers[i].buf, lpBuffers[i].len)) {
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = lpBuffers[i].len;
                return 0;
            }
            if (!GameState::instance().parseOutgoing(lpBuffers[i].buf, lpBuffers[i].len)) {
                debugLog("[WSASENDTO] blocked by Lua hook");
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = lpBuffers[i].len;
                return 0;
            }
        }
    }
    g_WsaSendToCount++;
    if (g_WsaSendToCount <= 60 && dwBufferCount > 0 && lpBuffers[0].buf && lpBuffers[0].len > 0) {
        if (lpBuffers[0].len >= 60) {
            char tag[64];
            snprintf(tag, sizeof(tag), "[WSASENDTO #%d]", g_WsaSendToCount);
            LogHexDump(tag, lpBuffers[0].buf, (int)lpBuffers[0].len);
            LogStack("SENDTO");
        } else {
            char hex[192] = {};
            int pos = 0;
            DWORD lim = lpBuffers[0].len < 48 ? lpBuffers[0].len : 48;
            for (DWORD i = 0; i < lim && pos < 180; i++) {
                pos += snprintf(hex + pos, 192 - pos, "%02X ", (unsigned char)lpBuffers[0].buf[i]);
            }
            char msg[288];
            snprintf(msg, sizeof(msg), "[WSASENDTO #%d] len=%d %s",
                     g_WsaSendToCount, (int)lpBuffers[0].len, hex);
            consoleLog(msg);
        }
    }
    GUARD_ORIG(WSASendTo, SOCKET_ERROR)
    return o_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                       to, iTolen, lpOverlapped, lpCompletionRoutine);
}

int WINAPI hk_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name && namelen >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)name;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        int port = ntohs(addr->sin_port);
        debugLog("[NET] connect: " + std::string(ip) + ":" + std::to_string(port));
        if (port == 17100 || port == 17101) {
            g_GameSocket = s;
            debugLog("[NET] Game socket detected!");
            // bothax GetClient — server endpoint for this session
            auto& gs = GameState::instance();
            std::lock_guard<std::mutex> lk(gs.mtx);
            gs.server_addr = ip;
            gs.server_port = port;
        }
    }
    GUARD_ORIG(connect, SOCKET_ERROR)
    return o_connect(s, name, namelen);
}

SOCKET WINAPI hk_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) {
    GUARD_ORIG(WSASocketW, INVALID_SOCKET)
    SOCKET s = o_WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
    SAVE_LAST_ERROR();
    debugLog("[NET] WSASocketW: af=" + std::to_string(af) + " type=" + std::to_string(type) + " proto=" + std::to_string(protocol) + " socket=" + std::to_string((int)s));
    RESTORE_LAST_ERROR();
    return s;
}

static void HookSocketFunction(HMODULE hWS2, const char* name, void* hook, void** original) {
    auto addr = (void*)GetProcAddress(hWS2, name);
    if (addr) {
        epshook::Status st = epshook::Create(addr, hook, original);
        if (st == epshook::OK) {
            char m[160];
            snprintf(m, sizeof(m), "[HOOK] %s hooked OK tgt=%p orig=%p", name, addr, original ? *original : nullptr);
            debugLog(m);
        } else {
            debugLog("[HOOK] " + std::string(name) + " hook FAILED: " + epshook::StatusString(st));
        }
    } else {
        debugLog("[HOOK] " + std::string(name) + " not found in ws2_32");
    }
}

static void InstallSocketHooks(HMODULE hWS2) {
    if (!hWS2) return;
    HookSocketFunction(hWS2, "send", (void*)hk_send, (void**)&o_send);
    HookSocketFunction(hWS2, "recv", (void*)hk_recv, (void**)&o_recv);
    HookSocketFunction(hWS2, "sendto", (void*)hk_sendto, (void**)&o_sendto);
    HookSocketFunction(hWS2, "recvfrom", (void*)hk_recvfrom, (void**)&o_recvfrom);
    HookSocketFunction(hWS2, "WSASend", (void*)hk_WSASend, (void**)&o_WSASend);
    HookSocketFunction(hWS2, "WSARecv", (void*)hk_WSARecv, (void**)&o_WSARecv);
    HookSocketFunction(hWS2, "WSARecvFrom", (void*)hk_WSARecvFrom, (void**)&o_WSARecvFrom);
    HookSocketFunction(hWS2, "WSASendTo", (void*)hk_WSASendTo, (void**)&o_WSASendTo);
    HookSocketFunction(hWS2, "connect", (void*)hk_connect, (void**)&o_connect);
    HookSocketFunction(hWS2, "WSASocketW", (void*)hk_WSASocketW, (void**)&o_WSASocketW);
    HookSocketFunction(hWS2, "WSAGetOverlappedResult", (void*)hk_WSAGetOverlappedResult, (void**)&o_WSAGetOverlappedResult);

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        auto pGQCS = (void*)GetProcAddress(hK32, "GetQueuedCompletionStatus");
        if (pGQCS) {
            epshook::Status st = epshook::Create(pGQCS, (void*)hk_GetQueuedCompletionStatus, (void**)&o_GetQueuedCompletionStatus);
            if (st == epshook::OK) consoleLog("[INFO] GetQueuedCompletionStatus hook installed");
            else consoleLog(std::string("[INFO] GQCS hook failed: ") + epshook::StatusString(st));
        }
    }
}

bool g_SocketHooksInstalled = false;

// ── TLS hooks (DecryptMessage) ──────────────────────────────────────
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <security.h>

typedef SECURITY_STATUS(WINAPI* DecryptMessage_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
static DecryptMessage_t o_DecryptMessage = nullptr;
static int g_TlsCount = 0;

SECURITY_STATUS WINAPI hk_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pulQOP) {
    SECURITY_STATUS status = o_DecryptMessage(phContext, pMessage, MessageSeqNo, pulQOP);

    if (status == SEC_E_OK && pMessage && pMessage->cBuffers >= 1) {
        for (ULONG i = 0; i < pMessage->cBuffers; i++) {
            SecBuffer* buf = &pMessage->pBuffers[i];
            if (buf->BufferType == SECBUFFER_DATA && buf->cbBuffer > 4 && buf->pvBuffer) {
                BYTE* data = (BYTE*)buf->pvBuffer;
                uint32_t header = *(uint32_t*)data;
                int pktType = header & 0xFF;

                g_TlsCount++;
                if (g_TlsCount <= 50) {
                    char hex[128] = {};
                    int pos = 0;
                    for (int j = 0; j < 32 && j < (int)buf->cbBuffer && pos < 120; j++) {
                        pos += snprintf(hex + pos, 128 - pos, "%02X ", data[j]);
                    }
                    char buf2[512];
                    snprintf(buf2, sizeof(buf2), "[TLS #%d] type=%d len=%d %s",
                        g_TlsCount, pktType, buf->cbBuffer, hex);
                    consoleLog(buf2);
                }

                if (pktType == 4 && buf->cbBuffer > 4) {
                    std::string text((char*)(data + 4), buf->cbBuffer - 4);
                    if (text.size() > 2) {
                        GameState::instance().parseTextPacket(text, true);
                    }
                }

                if ((pktType == 1 || pktType == 2 || pktType == 3) && buf->cbBuffer >= 16) {
                    GameState::instance().parseIncoming((const char*)data, buf->cbBuffer);
                }
            }
        }
    }

    return status;
}

void TryInstallTLSHooks() {
    HMODULE hSec = GetModuleHandleA("sspicli.dll");
    if (!hSec) hSec = GetModuleHandleA("secur32.dll");
    if (!hSec) hSec = GetModuleHandleA("schannel.dll");
    if (!hSec) {
        consoleLog("[INFO] No Windows TLS DLL loaded (sspicli/secur32/schannel) - game uses own TLS");
        return;
    }
    auto addr = (void*)GetProcAddress(hSec, "DecryptMessage");
    if (!addr) addr = (void*)GetProcAddress(hSec, "SslDecryptPacket");
    if (addr) {
        epshook::Status st = epshook::Create(addr, (void*)hk_DecryptMessage, (void**)&o_DecryptMessage);
        if (st == epshook::OK) {
            consoleLog("[INFO] TLS decrypt hook installed OK");
        } else {
            char buf[160];
            snprintf(buf, sizeof(buf), "[WARN] TLS decrypt hook failed: %s", epshook::StatusString(st));
            consoleLog(buf);
        }
    } else {
        consoleLog("[INFO] DecryptMessage/SslDecryptPacket not exported - game uses own TLS");
    }
}

void TryInstallSocketHooks() {
    if (g_SocketHooksInstalled) return;
    HMODULE hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) {
        hWS2 = LoadLibraryA("ws2_32.dll");
        if (hWS2) debugLog("[NET] ws2_32.dll force-loaded");
    }
    if (hWS2) {
        InstallSocketHooks(hWS2);
        g_SocketHooksInstalled = true;
        consoleLog("[INFO] Socket hooks installed (send/recv/WSA/connect)");
    }
}

// ── BCrypt decrypt hook ────────────────────────────────────────────
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef NTSTATUS (WINAPI* BCryptDecrypt_t)(
    BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
    void* pPaddingInfo, PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);

static BCryptDecrypt_t o_BCryptDecrypt = nullptr;
static int g_BCryptCount = 0;

NTSTATUS WINAPI hk_BCryptDecrypt(
    BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
    void* pPaddingInfo, PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{
    NTSTATUS status = o_BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo,
        pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    if (status >= 0 && pbOutput && cbOutput >= 4) {
        // cbOutput is the BUFFER CAPACITY; only *pcbResult bytes are plaintext.
        // Parsing past *pcbResult reads stale bytes and false-positives as packets.
        ULONG outLen = (pcbResult && *pcbResult > 0) ? *pcbResult : 0;
        bool isHttp = outLen >= 5 && pbOutput[0]=='H' && pbOutput[1]=='T' && pbOutput[2]=='T' && pbOutput[3]=='P';
        if (!isHttp) {
            g_BCryptCount++;
            if (g_BCryptCount <= 40) {
                char tag[64];
                snprintf(tag, sizeof(tag), "[BCRYPT-PLAIN #%d] cap=%lu written=%lu",
                         g_BCryptCount, cbOutput, outLen);
                LogHexDump(tag, pbOutput, (int)outLen);

                if (outLen >= 4) {
                    uint32_t header = *(uint32_t*)pbOutput;
                    int pktType = header & 0xFF;

                    if (pktType == 4 && outLen > 4) {
                        std::string text((char*)(pbOutput + 4), outLen - 4);
                        if (text.size() > 2) {
                            GameState::instance().parseTextPacket(text, true);
                            consoleLog("[BCRYPT] Parsed type=4 text packet, len=" + std::to_string(text.size()));
                        }
                    }

                    if ((pktType == 1 || pktType == 2 || pktType == 3) && outLen >= 16) {
                        GameState::instance().parseIncoming((const char*)pbOutput, (int)outLen);
                        consoleLog("[BCRYPT] Parsed type=" + std::to_string(pktType) + " raw packet");
                    }
                }
            }
        }
    }

    return status;
}

void TryInstallBCryptHooks() {
    const char* dlls[] = { "bcrypt.dll", "bcryptprimitives.dll" };
    for (const char* dll : dlls) {
        HMODULE h = GetModuleHandleA(dll);
        if (!h) h = LoadLibraryA(dll);
        if (!h) continue;

        auto addr = (void*)GetProcAddress(h, "BCryptDecrypt");
        if (addr && !o_BCryptDecrypt) {
            epshook::Status st = epshook::Create(addr, (void*)hk_BCryptDecrypt, (void**)&o_BCryptDecrypt);
            if (st == epshook::OK) {
                consoleLog("[INFO] BCryptDecrypt hooked in " + std::string(dll));
            } else {
                char buf[160];
                snprintf(buf, sizeof(buf), "[WARN] BCryptDecrypt hook failed: %s", epshook::StatusString(st));
                consoleLog(buf);
            }
        }
    }
    if (!o_BCryptDecrypt) {
        consoleLog("[INFO] BCryptDecrypt not found - game may use own crypto");
    }
}

// ── Main thread ──────────────────────────────────────────────────────

#if ENABLE_NATIVE_HOOK
// Packet capture via EpsHook CreateSpy (register-spy / observer mode).
// Spies resolved packet entry points; dumps regs + RCX/RDX payloads,
// parses type-4 text packets into OnVarlist events. Game flow untouched.

static int g_SpyHits = 0;
static std::map<std::string, int> g_SpyTagHits;

static bool SafeReadMem(uintptr_t p, void* out, size_t n) {
    if (p <= 0x10000 || p >= 0x7FFFFFFFFFFFull) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if (p + n > regionEnd) return false;
    __try { memcpy(out, (const void*)p, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Bounded readable C-string: printable ASCII + \n\r only, region-safe.
static bool SafeReadText(uintptr_t p, char* out, size_t cap, size_t* outLen) {
    if (p <= 0x10000 || p >= 0x7FFFFFFFFFFFull) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    size_t max = regionEnd - p;
    if (max > cap - 1) max = cap - 1;
    size_t n = 0;
    __try {
        n = strnlen((const char*)p, max);
        if (n < 4) return false;
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)((const char*)p)[i];
            if (c < 0x20 && c != '\n' && c != '\r') return false;
        }
        memcpy(out, (const void*)p, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    out[n] = 0;
    *outLen = n;
    return true;
}

// Class identity via vtable address (RTTI names stripped from this build —
// ??_R0 string count = 0 in image_mem.bin). Logs each distinct in-module
// vtable once: [SPY:VFT] vf=0x... — map offline against the dump.
static void LogRttiClass(const void* obj) {
    static std::map<uintptr_t, bool> seenVf;
    uint64_t vf = 0;
    if (!SafeReadMem((uintptr_t)obj, &vf, 8)) return;
    if (vf >= 0x7FFFFFFFFFFFull) return;
    HMODULE hGame = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)vf, &hGame)) return;  // not in any module (heap ptr) — skip
    if (seenVf.count(vf)) return;
    seenVf[vf] = true;
    char buf[96];
    snprintf(buf, sizeof(buf), "[SPY:VFT] vf=0x%llX",
             (unsigned long long)vf);
    consoleLog(buf);
}

static void SpyDump(const char* tag, epshook::SavedRegs* regs) {
    g_SpyHits++;
    int& n = g_SpyTagHits[tag];
    n++;
    if (n > 60) return;

    char buf[512];
    snprintf(buf, sizeof(buf),
        "[SPY:%s #%d] RAX=0x%llX RCX=0x%llX RDX=0x%llX R8=0x%llX",
        tag, n,
        (unsigned long long)regs->rax, (unsigned long long)regs->rcx,
        (unsigned long long)regs->rdx, (unsigned long long)regs->r8);
    consoleLog(buf);

    uintptr_t candidates[2] = { regs->rcx, regs->rdx };
    for (int c = 0; c < 2; c++) {
        uintptr_t dataPtr = candidates[c];
        MEMORY_BASIC_INFORMATION mbi = {};
        if (dataPtr <= 0x10000 || dataPtr >= 0x7FFFFFFFFFFF) continue;
        if (!VirtualQuery((void*)dataPtr, &mbi, sizeof(mbi))) continue;
        if (mbi.State != MEM_COMMIT) continue;

        char hex[512] = {};
        int pos = 0;
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        for (unsigned int i = 0; i < 64 && pos < 470 && dataPtr + i < regionEnd; i++) {
            unsigned char b = ((unsigned char*)dataPtr)[i];
            pos += snprintf(hex + pos, 512 - pos, "%02X ", b);
            if ((i + 1) % 32 == 0) pos += snprintf(hex + pos, 512 - pos, "\n    ");
        }
        snprintf(buf, sizeof(buf), "[SPY:%s] %s data: %s", tag, c ? "RDX" : "RCX", hex);
        consoleLog(buf);

        if (dataPtr + 4 > regionEnd) continue;
        uint32_t header = *(uint32_t*)dataPtr;
        int pktType = header & 0xFF;
        if (pktType == 4) {
            const char* text = (const char*)(dataPtr + 4);
            bool valid = true;
            // never read past the committed region we just queried
            size_t maxLen = (dataPtr + 4 < regionEnd) ? (regionEnd - (dataPtr + 4)) : 0;
            size_t tlen = (maxLen > 0) ? strnlen(text, maxLen < 256 ? maxLen : 256) : 0;
            for (size_t i = 0; i < tlen; i++) {
                if ((unsigned char)text[i] < 0x20 && text[i] != '\n' && text[i] != '\r') { valid = false; break; }
            }
            if (valid && tlen > 4) {
                std::string pktText(text, tlen);
                GameState::instance().parseTextPacket(pktText, true);
                consoleLog("[SPY:" + std::string(tag) + "] TEXT: " + pktText.substr(0, 200));
            }
        }
    }
}

// game ctx pointer (Creative build: captured from rcx at the type-4
// gamepacket spy; Growtopia build: via scanner::fn_GetCtx) — declared before
// spy_ptup so the spy can store it.
static std::atomic<uintptr_t> g_GameCtx{0};

static void spy_ptup(epshook::SavedRegs* r) {
    SpyDump("PTUP", r);
    // rdx = packet struct on the pump's stack; [rdx+0x18] = message object
    // (helper target of the type-switch), [rdx+8] = companion object.
    uintptr_t msgObj = 0, alt = 0;
    if (SafeReadMem((uintptr_t)r->rdx + 0x18, &msgObj, 8)) LogRttiClass((const void*)msgObj);
    if (SafeReadMem((uintptr_t)r->rdx + 0x08, &alt, 8)) LogRttiClass((const void*)alt);
    // struct dword0 changes? (observed constant 3 so far)
    uint32_t t0 = 0;
    static uint32_t s_lastT0 = 0xFFFFFFFFu;
    static DWORD s_t0LogT = 0;
    static int s_t0Total = 0;
    if (SafeReadMem((uintptr_t)r->rdx, &t0, 4) && t0 != s_lastT0) {
        s_lastT0 = t0;
        DWORD nowT = GetTickCount();
        if (s_t0Total < 40 && (!s_t0LogT || nowT - s_t0LogT >= 1000)) {
            s_t0LogT = nowT;
            s_t0Total++;
            char b[80];
            snprintf(b, sizeof(b), "[SPY:PTUP] struct dword0=%u (change-tracked)", t0);
            consoleLog(b);
        }
    }
    // type/size probe — [msgObj+0x10]=buffer ptr, [msgObj+0x18]=size,
    // buffer[0]=packet type, payload at +4 (dispatcher getters 0x140C43550
    // / 0x140C45270 / type-9 raw path all agree). First 3 hits per type +
    // any packet >4KB (world-data sized) so a world join maps every type.
    uintptr_t buf = 0;
    uint64_t bsz = 0;
    if (msgObj > 0x10000 &&
        SafeReadMem(msgObj + 0x10, &buf, 8) &&
        SafeReadMem(msgObj + 0x18, &bsz, 8) &&
        buf > 0x10000 && bsz >= 4 && bsz <= 64ull * 1024 * 1024) {
        unsigned char bType = 0;
        if (SafeReadMem(buf, &bType, 1)) {
            static int s_TypeHits[16] = {};
            static int s_BigLogged = 0;
            bool logIt = false;
            if (bType < 16 && s_TypeHits[bType] < 3) { s_TypeHits[bType]++; logIt = true; }
            if (bsz > 4096 && s_BigLogged < 8) { s_BigLogged++; logIt = true; }
            if (logIt) {
                unsigned char head[8] = {};
                SafeReadMem(buf + 4, head, 8);
                auto pr = [](unsigned char c) -> char {
                    return (c >= 32 && c < 127) ? (char)c : '.';
                };
                char b[240];
                snprintf(b, sizeof(b),
                    "[PTUP2] type=%u pkt0=%u size=%llu head=%02X %02X %02X %02X %02X %02X %02X %02X '%c%c%c%c%c%c%c%c'",
                    bType, t0, (unsigned long long)bsz,
                    head[0], head[1], head[2], head[3],
                    head[4], head[5], head[6], head[7],
                    pr(head[0]), pr(head[1]), pr(head[2]), pr(head[3]),
                    pr(head[4]), pr(head[5]), pr(head[6]), pr(head[7]));
                consoleLog(b);
            }
            // unbounded subtype histogram (bounded log: 2 hits per subtype
            // + summary every 250 type-4 packets) — geiger channel hunt
            if (bType == 3 || bType == 4) {
                static std::map<uint32_t, uint32_t> s_SubCnt;
                static std::map<uint32_t, int> s_SubLog;
                unsigned char sub = 0;
                if (SafeReadMem(buf + 4, &sub, 1)) {
                    uint32_t key = ((uint32_t)bType << 8) | sub;
                    s_SubCnt[key]++;
                    if (s_SubLog[key] < 2) {
                        s_SubLog[key]++;
                        unsigned char h16[16] = {};
                        SafeReadMem(buf + 4, h16, 16);
                        char b2[300];
                        int p = snprintf(b2, sizeof(b2),
                            "[SUBT] t%u sub=0x%02X n=%u size=%llu head=",
                            bType, sub, s_SubCnt[key], (unsigned long long)bsz);
                        for (int i = 0; i < 16 && p < (int)sizeof(b2) - 4; i++)
                            p += snprintf(b2 + p, sizeof(b2) - p, " %02X", h16[i]);
                        consoleLog(b2);
                    }
                    if (bType == 4 && s_SubCnt[key] % 250 == 0) {
                        static DWORD s_subsumT = 0;
                        DWORD nowS = GetTickCount();
                        if (!s_subsumT || nowS - s_subsumT >= 5000) {
                            s_subsumT = nowS;
                            std::string s;
                            for (auto& kv : s_SubCnt)
                                if (kv.first >> 8 == 4) {
                                    char tmp[24];
                                    snprintf(tmp, sizeof(tmp), " %02X:%u",
                                        kv.first & 0xFF, kv.second);
                                    s += tmp;
                                    if (s.size() > 380) break;
                                }
                            std::string line = "[SUBSUM]" + s;
                            consoleLog(line.c_str());
                        }
                    }
                    // full packet capture for tank type 17 (geiger ring) —
                    // verifies the xspeed offset empirically (expect a
                    // 1.00f/2.00f float somewhere in the payload)
                    if (bType == 4 && sub == 0x11) {
                        static int s_RingHexN = 0;
                        if (s_RingHexN < 40) {
                            s_RingHexN++;
                            unsigned char hx[64] = {};
                            size_t rn = bsz < 64 ? (size_t)bsz : 64;
                            SafeReadMem(buf, hx, rn);
                            char hb[240];
                            int p = snprintf(hb, sizeof(hb),
                                "[RINGHEX] #%d size=%llu:", s_RingHexN,
                                (unsigned long long)bsz);
                            for (size_t i = 0; i < rn && p < (int)sizeof(hb) - 4; i++)
                                p += snprintf(hb + p, sizeof(hb) - p, " %02X", hx[i]);
                            consoleLog(hb);
                        }
                    }
                    // login-response payload discovery (sub 1) + sub 9 — the
                    // gems/account record the HUD reads; dump raw preview to
                    // identify field names for state parsing.
                    if (bType == 4 && (sub == 0x01 || sub == 0x09)) {
                        static int s_LoginDump = 0;
                        if (s_LoginDump < 24) {
                            s_LoginDump++;
                            unsigned char raw[400] = {};
                            size_t rn = bsz < 400 ? (size_t)bsz : 400;
                            SafeReadMem(buf + 4, raw, rn);
                            char prev[240];
                            int p = snprintf(prev, sizeof(prev),
                                "[LOGINPAY] sub=0x%02X size=%llu head32:",
                                sub, (unsigned long long)bsz);
                            for (int i = 0; i < 32 && p < (int)sizeof(prev) - 5; i++)
                                p += snprintf(prev + p, sizeof(prev) - p, " %02X", raw[i]);
                            p += snprintf(prev + p, sizeof(prev) - p, " TXT:");
                            for (size_t i = 16; i < rn && p < (int)sizeof(prev) - 2; i++) {
                                unsigned char c = raw[i];
                                char ch = (c == 0) ? '|' : ((c >= 32 && c < 127) ? (char)c : '.');
                                prev[p++] = ch;
                            }
                            prev[p] = 0;
                            consoleLog(prev);
                            // needle scan for gem/account fields in the full
                            // varlist payload (length-prefixed binary values)
                            if (bsz <= 4096) {
                                std::vector<unsigned char> full((size_t)bsz);
                                if (SafeReadMem(buf + 4, full.data(), (size_t)bsz)) {
                                    // OnSetBux = gems balance update. Payload
                                    // shape (this GTPS): "OnSetBux" then
                                    // arg1 = 01 09 <u32 LE gems>. Feed it back
                                    // through parseTextPacket so state, events
                                    // and lua OnVariant hooks all see it.
                                    const unsigned char* f = full.data();
                                    for (size_t i = 0; i + 14 < full.size(); i++) {
                                        if (memcmp(f + i, "OnSetBux", 8) == 0 &&
                                            f[i + 8] == 0x01 && f[i + 9] == 0x09) {
                                            uint32_t g = (uint32_t)f[i + 10] |
                                                ((uint32_t)f[i + 11] << 8) |
                                                ((uint32_t)f[i + 12] << 16) |
                                                ((uint32_t)f[i + 13] << 24);
                                            char mg[96];
                                            snprintf(mg, sizeof(mg),
                                                "[GEMS] OnSetBux parse -> %u", g);
                                            consoleLog(mg);
                                            GameState::instance().parseTextPacket(
                                                "OnSetBux\n" + std::to_string(g), true);
                                            break;
                                        }
                                    }
                                    static const char* kNeedles[] = {
                                        "gems", "Gems", "Bux", "bux", "OnSetBux",
                                        "GemsCount", "wallet", "coins"
                                    };
                                    for (const char* nd : kNeedles) {
                                        size_t nl = strlen(nd);
                                        for (size_t i = 0; i + nl < full.size(); i++) {
                                            if (memcmp(full.data() + i, nd, nl) == 0) {
                                                char hit[300];
                                                int q = snprintf(hit, sizeof(hit),
                                                    "[NEEDLE] '%s' @%zu/%llu ctx: ", nd, i,
                                                    (unsigned long long)bsz);
                                                size_t s0 = i > 40 ? i - 40 : 0;
                                                for (size_t j = s0; j < full.size() && j < i + 80 && q < 280; j++) {
                                                    unsigned char c = full[j];
                                                    hit[q++] = (c == 0) ? '|' : ((c >= 32 && c < 127) ? (char)c : '.');
                                                }
                                                hit[q] = 0;
                                                consoleLog(hit);
                                                if (strcmp(nd, "OnSetBux") == 0) {
                                                    static int s_BuxHexN = 0;
                                                    if (s_BuxHexN < 6) {
                                                        s_BuxHexN++;
                                                        char hx[420];
                                                        int z = snprintf(hx, sizeof(hx),
                                                            "[BUXHEX] #%d size=%llu:", s_BuxHexN,
                                                            (unsigned long long)bsz);
                                                        for (size_t j = 0; j < full.size() && z < 400; j++)
                                                            z += snprintf(hx + z, sizeof(hx) - z, " %02X", full[j]);
                                                        consoleLog(hx);
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // OnTankPacket feed — when a Lua listener exists. Tank struct =
            // buf+4 (PlayerMoving): +4 netid, +12 state, +20 plantingTree,
            // +24 x, +28 y, +32 xspeed, +36 yspeed.
            // tank type 0 (movement spam) is skipped to protect the queue.
            // Exception: type 34 (NPC state) always feeds GetNPC/GetNPCList
            // even with no OnTankPacket listener.
            if (bType == 4 && bsz >= 60) {
                uint32_t tankType = 0;
                if (SafeReadMem(buf + 4, &tankType, 4)) {
                    bool isNpc = (tankType & 0xFF) == 34;
                    bool want = g_OnTankPacket.load(std::memory_order_relaxed);
                    if ((tankType != 0 && want) || isNpc) {
                        PacketEvent ev;
                        ev.type = "OnTankPacket";
                        ev.packet_type = (int)(tankType & 0xFF); // byte0 only — u32 also holds netid/count
                        int32_t iv = 0;
                        if (SafeReadMem(buf + 8, &iv, 4)) ev.netid = iv;
                        if (SafeReadMem(buf + 16, &iv, 4)) ev.flags = iv;
                        if (SafeReadMem(buf + 24, &iv, 4)) ev.int_data = iv;
                        SafeReadMem(buf + 28, &ev.pos_x, 4);
                        SafeReadMem(buf + 32, &ev.pos_y, 4);
                        SafeReadMem(buf + 36, &ev.xspeed, 4);
                        SafeReadMem(buf + 40, &ev.yspeed, 4);
                        SafeReadMem(buf + 48, &ev.pos2_x, 4);  // struct+44 px
                        SafeReadMem(buf + 52, &ev.pos2_y, 4);  // struct+48 py
                        GameState::instance().pushEvent(ev);
                    }
                }
            }
        }
    } else {
        // Creative build: this spy sits on the type-4 gamepacket processor
        // (base+0xCB030) where rcx = game ctx and rdx = the GameUpdatePacket
        // struct itself (type byte @+0). The Growtopia msgObj contract above
        // misreads here (its probe fails) — fall back to this layout.
        uintptr_t ctxv = (uintptr_t)r->rcx;
        if (ctxv > 0x100000 && ctxv < 0x00007FFFFFFF0000ULL) {
            g_GameCtx.store(ctxv, std::memory_order_relaxed);
        }
        uintptr_t st = (uintptr_t)r->rdx;
        uint32_t tankType = 0;
        if (st > 0x10000 && st < 0x7FFFFFFFFFFFull &&
            SafeReadMem(st, &tankType, 4)) {
            bool isNpc = (tankType & 0xFF) == 34;
            bool want = g_OnTankPacket.load(std::memory_order_relaxed);
            if ((tankType != 0 && want) || isNpc) {
                PacketEvent ev;
                ev.type = "OnTankPacket";
                ev.packet_type = (int)(tankType & 0xFF);
                int32_t iv = 0;
                if (SafeReadMem(st + 4, &iv, 4)) ev.netid = iv;
                if (SafeReadMem(st + 12, &iv, 4)) ev.flags = iv;
                if (SafeReadMem(st + 20, &iv, 4)) ev.int_data = iv;
                SafeReadMem(st + 24, &ev.pos_x, 4);
                SafeReadMem(st + 28, &ev.pos_y, 4);
                SafeReadMem(st + 32, &ev.xspeed, 4);
                SafeReadMem(st + 36, &ev.yspeed, 4);
                SafeReadMem(st + 44, &ev.pos2_x, 4);
                SafeReadMem(st + 48, &ev.pos2_y, 4);
                GameState::instance().pushEvent(ev);
            }
        }
    }
}
// Real SendPacket chokepoint (detour, dump-verified @0x140C464C0):
//   fn(int type /*ecx*/, std::string* payload /*rdx*/, void* conn /*r8*/)
// MSVC std::string { SSO/ptr @0, size @0x10, cap @0x18 } — SSO when cap<=15.
// Registered slash-commands are dispatched to Lua and the original call is
// skipped entirely, so the server never sees them. All other traffic flows
// through untouched; text-ish payloads also emit GrowPai-parity OnPacket.
using SendPacket_t = void(*)(int, std::string*, void*);
static SendPacket_t o_SendPacket = nullptr;

static void hk_SendPacket(int type, std::string* pkt, void* conn) {
    bool forward = true;
    if (pkt && type >= 0 && type <= 32) {
        size_t sz = 0, cap = 0;
        if (SafeReadMem((uintptr_t)pkt + 0x10, &sz, 8) &&
            SafeReadMem((uintptr_t)pkt + 0x18, &cap, 8) &&
            sz > 0 && sz <= 65536) {
            const char* data = nullptr;
            std::string heap;
            if (cap <= 15) {
                unsigned char probe = 0;
                if (SafeReadMem((uintptr_t)pkt, &probe, 1)) data = (const char*)pkt;
            } else {
                uintptr_t dp = 0;
                if (SafeReadMem((uintptr_t)pkt, &dp, 8) &&
                    dp > 0x10000 && dp < 0x7FFFFFFFFFFFull) {
                    heap.resize(sz);
                    if (SafeReadMem(dp, &heap[0], sz)) data = heap.c_str();
                }
            }
            if (data) {
                if (GameState::instance().interceptCommand(data, (int)sz)) {
                    char m[160];
                    snprintf(m, sizeof(m), "[SENDPKT] suppressed type=%d len=%zu",
                             type, sz);
                    consoleLog(m);
                    forward = false;
                } else {
                    // outbound histogram: bounded 2 logs per (type,firstbyte)
                    static std::map<uint32_t, uint32_t> s_OCnt;
                    static std::map<uint32_t, int> s_OLog;
                    uint32_t okey = ((uint32_t)type << 16) | (unsigned char)data[0];
                    s_OCnt[okey]++;
                    if (s_OLog[okey] < 2) {
                        s_OLog[okey]++;
                        unsigned char h[16] = {};
                        size_t n = sz < 16 ? sz : 16;
                        memcpy(h, data, n);
                        char ob[300];
                        int p = snprintf(ob, sizeof(ob),
                            "[OUTT] type=%d b0=0x%02X n=%u size=%zu head=",
                            type, (unsigned char)data[0], s_OCnt[okey], sz);
                        for (size_t i = 0; i < n && p < (int)sizeof(ob) - 4; i++)
                            p += snprintf(ob + p, sizeof(ob) - p, " %02X", h[i]);
                        consoleLog(ob);
                    }
                    // text-ish outbound? (type 2/4 + printable payload)
                    bool textish = (type == 2 || type == 4);
                    if (textish) {
                        size_t chk = sz < 64 ? sz : 64;
                        for (size_t i = 0; i < chk; i++) {
                            unsigned char c = (unsigned char)data[i];
                            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                                textish = false; break;
                            }
                        }
                    }
                    // bothax sync hooks — dispatch HERE at the app layer
                    // (payload still plaintext; the socket/TLS layers only
                    // see encrypted bytes). return true = suppress send.
                    if (textish) {
                        if (LuaHooks::dispatchSendPacket(type, std::string(data, sz))) {
                            consoleLog("[SENDPKT] Lua hook blocked type=" +
                                       std::to_string(type) + " len=" + std::to_string(sz));
                            forward = false;
                        }
                    } else if (LuaHooks::dispatchSendPacketRaw(data, (int)sz)) {
                        consoleLog("[SENDPKT] Lua raw hook blocked type=" +
                                   std::to_string(type) + " len=" + std::to_string(sz));
                        forward = false;
                    }
                    if (forward)
                    {
                    // our own movement (client physics or injected walk) —
                    // ground-truth netid + position sync for localPlayer
                    if (type == 4 && sz >= 32 && data[0] == 0) {
                        int32_t onet = 0, ostate = 0;
                        float ox = 0, oy = 0;
                        memcpy(&onet, data + 4, 4);
                        memcpy(&ostate, data + 12, 4);
                        memcpy(&ox, data + 24, 4);
                        memcpy(&oy, data + 28, 4);
                        auto& gs = GameState::instance();
                        static int s_MeLog = 0;
                        {
                            std::unique_lock<std::mutex> gl(gs.mtx, std::try_to_lock);
                            if (gl.owns_lock()) {
                                if (onet >= 0 && onet != gs.localPlayer.netid) {
                                    if (s_MeLog < 10) {
                                        s_MeLog++;
                                        char mb[140];
                                        snprintf(mb, sizeof mb,
                                                 "[ME] own-state netid %d -> %d pos=(%.0f,%.0f)",
                                                 gs.localPlayer.netid, onet, ox, oy);
                                        consoleLog(mb);
                                    }
                                    gs.localPlayer.netid = onet;
                                }
                                gs.localPlayer.pos_x = ox;
                                gs.localPlayer.pos_y = oy;
                                gs.localPlayer.tile_x = (int)(ox / 32);
                                gs.localPlayer.tile_y = (int)(oy / 32);
                                gs.localPlayer.flags = ostate;
                            }
                        }
                    }
                    // text-ish outbound -> OnPacket(type, text) for lua parity
                    if (textish) {
                        PacketEvent ev;
                        ev.type = "OnPacket";
                        ev.packet_type = type;
                        ev.text.assign(data, sz);
                        GameState::instance().pushEvent(ev);
                    }
                    } // if (forward)
                }
            }
        }
    }
    if (forward && o_SendPacket) o_SendPacket(type, pkt, conn);
}

// ── Live game-structure caches (per-build dump-verified layouts) ───────────
// Growtopia.exe (GT):
// ctx    = call 0x140B2D9D0()  (global 0-arg getter, captured on game thread)
// world  = *[ctx+0x110]
//   world+0x90 / +0x94 : u32 width / height      (WorldTileMap header)
//   world+0xA0 / +0xA8 : tile vector begin / end (stride 0xF0 = 240 B/tile)
//     tile+0x50 u16 fg, tile+0x52 u16 bg, tile+0x58 u16 flags, idx = y*w+x
//   world+0x118        : world-object list sentinel ptr; first = *[sent];
//     node+0 = next, entry @ node+0x10 = {s32 a, s32 b, u16 id, u8, u8,
//                                          s32 seq, s32 c, s32 d}
//   world+0x1F0/+0x200 : world name SSO / len
// PlayerItems container @ ctx+0x210:
//   +0x40 list sentinel ptr; node+0 = next;
//   entry {u16 id @+0x10, u8 count @+0x12, u8 flags @+0x13}  (count <= 255)
//
// CreativeGrowtopia.exe (CG, small ASLR image — scanner::IsCreativeBuild()):
// ctx    = *(*(base+0x3AC438) + 0xA98)      (no fn_GetCtx; see below)
// world  = *[ctx+0x138]
//   world+0x0C / +0x10 : u32 width / height (200x200 observed)
//   world+0x18 / +0x20 : tile vector begin / end (stride 63 B/tile)
//     tile+0 u16 flags, tile+4 u16 fg, tile+40 u16 bg (no wire words),
//     tile+8 u16 idx (= y*w+x), x@+6 y@+7
//   world+0x78         : world-object list sentinel ptr; first = *[sent];
//     node+0 next, node+8 prev, entry @ node+0x10 =
//     {f32 a, f32 x, f32 y, u16 id, u8, u8, s32 seq, s32 c, s32 d} (28 B)
//   world+0x90/+0xA0   : world name SSO / len ("BFGOF" observed)
//   inventory: container NOT yet located (v1 returns empty; TODO)
// tile vector base/dims captured by SyncGameCaches — bothax SetTileFlags
// writes the u16 flag word directly at begin + idx*stride + flagsOff
std::atomic<uintptr_t> g_TileBegin{0};
std::atomic<int> g_TileW{0};
std::atomic<int> g_TileH{0};

void SyncGameCaches(bool log) {
    // rate-limit passive (lua-triggered) refreshes; forced on world load
    static DWORD s_Last = 0;
    DWORD now = GetTickCount();
    if (!log && s_Last && now - s_Last < 250) return;
    s_Last = now;
    auto& gs = GameState::instance();
    uintptr_t ctx = g_GameCtx.load(std::memory_order_relaxed);
    if (!ctx && scanner::fn_GetCtx) {
        typedef uintptr_t (*GetCtx_t)();
        ctx = (uintptr_t)((GetCtx_t)scanner::fn_GetCtx)();
        if (ctx) g_GameCtx.store(ctx, std::memory_order_relaxed);
    }
    if (!ctx && !scanner::fn_GetCtx && scanner::g_GameBase) {
        // Creative build has no fn_GetCtx — ctx = *(*(base+0x3AC438) + 0xA98)
        // (the dispatcher loads [rip→.data 0x3AC438] then [+0xA98] before the
        // type-4 gamepacket call; verified against a live Creative dump).
        uintptr_t p = 0, c2 = 0;
        if (SafeReadMem(scanner::g_GameBase + 0x3AC438ULL, &p, 8) &&
            p > 0x10000 && p < 0x7FFFFFFFFFFFull &&
            SafeReadMem(p + 0xA98ULL, &c2, 8) &&
            c2 > 0x10000 && c2 < 0x7FFFFFFFFFFFull) {
            ctx = c2;
            g_GameCtx.store(ctx, std::memory_order_relaxed);
        }
    }
    static int s_SyncFail = 0;
    auto syncFail = [&](const char* why) {
        g_TileBegin.store(0, std::memory_order_relaxed);
        if (s_SyncFail < 6) {
            s_SyncFail++;
            char b[128];
            snprintf(b, sizeof(b), "[SYNCFAIL] %s ctx=0x%llX", why, (unsigned long long)ctx);
            consoleLog(b);
        }
    };
    if (!ctx) { syncFail("ctx"); return; }
    const bool cg = scanner::IsCreativeBuild();
    const uintptr_t stride = cg ? 63u : 0xF0u;
    uintptr_t world = 0;
    const uintptr_t kWorldOff = cg ? 0x138 : 0x110;
    if (!SafeReadMem(ctx + kWorldOff, &world, 8) || !world) { syncFail("world"); return; }
    // world pointer changed (join / door change) — stale NPC list must go;
    // replaces the LoadFromMem hook on builds where that hook is unavailable
    static uintptr_t s_LastWorld = 0;
    bool worldChanged = (world != s_LastWorld);
    if (worldChanged) {
        s_LastWorld = world;
        std::lock_guard<std::mutex> lk(gs.mtx);
        gs.npcs.clear();
    }
    uint32_t w = 0, h = 0;
    const uintptr_t kWOff = cg ? 0x0C : 0x90;
    const uintptr_t kHOff = cg ? 0x10 : 0x94;
    if (!SafeReadMem(world + kWOff, &w, 4) || !SafeReadMem(world + kHOff, &h, 4)) { syncFail("dims"); return; }
    if (w == 0 || h == 0 || w > 600 || h > 600 || (uint64_t)w * h > 66000) { syncFail("dims-range"); return; }
    uintptr_t begin = 0, end = 0;
    const uintptr_t kBeginOff = cg ? 0x18 : 0xA0;
    const uintptr_t kEndOff = cg ? 0x20 : 0xA8;
    SafeReadMem(world + kBeginOff, &begin, 8);
    SafeReadMem(world + kEndOff, &end, 8);
    if (!begin || end <= begin || (end - begin) < (uintptr_t)w * h * stride) { syncFail("span"); return; }
    g_TileBegin.store(begin, std::memory_order_relaxed);
    g_TileW.store((int)w, std::memory_order_relaxed);
    g_TileH.store((int)h, std::memory_order_relaxed);

    // world name SSO (GT +0x1F0/+0x200; CG +0x90/+0xA0)
    // (MSVC std::string: inline <=15 chars, else heap ptr)
    const uintptr_t kNameOff = cg ? 0x90 : 0x1F0;
    const uintptr_t kNameLenOff = cg ? 0xA0 : 0x200;
    char wname[32] = {};
    bool nameOk = false;
    {
        uint64_t nlen = 0;
        if (SafeReadMem(world + kNameLenOff, &nlen, 8) && nlen > 0 && nlen < sizeof(wname)) {
            if (nlen <= 15) {
                SafeReadMem(world + kNameOff, wname, (size_t)nlen);
            } else {
                uintptr_t nptr = 0;
                if (SafeReadMem(world + kNameOff, &nptr, 8) && nptr > 0x10000 && nptr < 0x7FFFFFFFFFFFull)
                    SafeReadMem(nptr, wname, (size_t)nlen);
            }
            wname[nlen] = 0;
            nameOk = true;
            for (size_t i = 0; wname[i] && nameOk; i++) {
                unsigned char c = (unsigned char)wname[i];
                if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) nameOk = false;
            }
        }
    }

    size_t count = (size_t)w * h;
    std::vector<uint8_t> raw(count * stride);
    bool tilesOk = true;
    for (size_t off = 0; off < raw.size();) {
        size_t n = raw.size() - off;
        if (n > 0x10000) n = 0x10000;
        if (!SafeReadMem(begin + off, raw.data() + off, n)) { tilesOk = false; break; }
        off += n;
    }

    std::vector<std::vector<TileData>> tiles;
    if (tilesOk) {
        const uintptr_t bgOff = cg ? 40u : 0x50u;
        const uintptr_t wireOff = cg ? 0u : 0xC0u;
        const uintptr_t flgOff = cg ? 0u : 0x52u;
        tiles.assign(h, std::vector<TileData>(w));
        for (size_t i = 0; i < count; i++) {
            const uint8_t* t = raw.data() + i * stride;
            uint16_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
            std::memcpy(&w0, t + 0x04, 2);   // fg  (set_fg writes +0x4 on both)
            std::memcpy(&w1, t + bgOff, 2);
            if (wireOff) std::memcpy(&w2, t + wireOff, 2); else w2 = 0;
            std::memcpy(&w3, t + flgOff, 2);
            TileData& td = tiles[(int)(i / w)][(int)(i % w)];
            td.fg = w0; td.bg = w1;
            td.extra = w2;
            td.flags = w3;
            td.pos_x = (int)(i % w); td.pos_y = (int)(i / w);
            td.ready = true;
        }
    }

    // world objects (list sentinel ptr @ world+0x118 GT / +0x78 CG)
    std::vector<WorldObject> objs;
    uintptr_t sent = 0;
    const uintptr_t kObjOff = cg ? 0x78 : 0x118;
    if (SafeReadMem(world + kObjOff, &sent, 8) && sent > 0x10000 && sent < 0x7FFFFFFFFFFFull) {
        uintptr_t node = 0;
        if (SafeReadMem(sent, &node, 8)) {
            int guard = 0;
            while (node && node != sent && guard++ < 4096) {
                WorldObject o;
                bool push = false;
                if (cg) {
                    // {f32 a, f32 x, f32 y, u16 id, u8, u8, s32 seq, s32 c, s32 d}
                    struct RObjC { float a, x, y; uint16_t id; uint8_t f1, f2; int32_t seq, c, d; } r{};
                    if (SafeReadMem(node + 0x10, &r, sizeof r)) {
                        // sentinel/foreign nodes fail this filter; real objects
                        // sit in pixel coords (<= world span) with sane ids
                        if (r.id > 0 && r.id < 20000 && r.x > -1e6f && r.x < 1e6f &&
                            r.y > -1e6f && r.y < 1e6f) {
                            o.id = r.id; o.oid = r.seq;
                            o.pos_x = r.x; o.pos_y = r.y;
                            o.count = r.c; o.flags = r.d;
                            push = true;
                        }
                    }
                } else {
                    struct RObj { float a, b; uint16_t id; uint8_t f1, f2; int32_t seq, c, d; } r{};
                    if (SafeReadMem(node + 0x10, &r, sizeof r)) {
                        o.id = r.id; o.oid = r.seq;
                        o.pos_x = r.a; o.pos_y = r.b;
                        o.count = r.c; o.flags = r.d;
                        push = true;
                    }
                }
                if (push) objs.push_back(o);
                if (!SafeReadMem(node, &node, 8)) break;
            }
        }
    }

    // PlayerItems list (ctx+0x210 + 0x40 sentinel) — GT layout only;
    // CG inventory container not yet located (v1: stays empty, see header)
    std::vector<InventoryItem> inv;
    uintptr_t isent = 0;
    if (!cg) {
    if (SafeReadMem(ctx + 0x210 + 0x40, &isent, 8) &&
        isent > 0x10000 && isent < 0x7FFFFFFFFFFFull) {
        uintptr_t node = 0;
        if (SafeReadMem(isent, &node, 8)) {
            int guard = 0;
            while (node && node != isent && guard++ < 4096) {
                uint16_t id = 0; uint8_t cnt = 0, fl = 0;
                if (!SafeReadMem(node + 0x10, &id, 2)) break;
                SafeReadMem(node + 0x12, &cnt, 1);
                SafeReadMem(node + 0x13, &fl, 1);
                if (id > 0 && id < 9638) {
                    InventoryItem it;
                    it.id = id;
                    it.count = cnt;
                    it.flags = fl;
                    inv.push_back(it);
                }
                if (!SafeReadMem(node, &node, 8)) break;
            }
        }
    }
    } // if (!cg)

    // capture sizes BEFORE swap empties the locals
    size_t nT = tilesOk ? (size_t)w * h : 0;
    size_t nO = objs.size(), nI = inv.size();

    bool changed = worldChanged;
    if (tilesOk) {
        std::lock_guard<std::mutex> lk(gs.mtx);
        if (gs.world_size_x != (int)w || gs.world_size_y != (int)h) changed = true;
        if (nameOk && gs.localPlayer.world != wname) changed = true;
        gs.world_size_x = (int)w;
        gs.world_size_y = (int)h;
        if (nameOk) gs.localPlayer.world = wname;
        gs.tiles.swap(tiles);
        gs.objects.swap(objs);
        gs.inventory.swap(inv);
    } else {
        syncFail("tiles-read");
    }

    // one-shot raw dump of the inventory container head for layout triage
    // (GT layout only — the CG container is not at ctx+0x210)
    static int s_Dbg = 0;
    if (!cg && s_Dbg < 3) {
        uint8_t b[96] = {};
        if (SafeReadMem(ctx + 0x210, b, sizeof b)) {
            char line[420];
            int p = snprintf(line, sizeof(line),
                "[SYNCDBG] inv=%zu (sent=%p) cont:", nI, (void*)isent);
            for (size_t i = 0; i < 48 && p < (int)sizeof(line) - 4; i++)
                p += snprintf(line + p, sizeof(line) - p, " %02X", b[i]);
            s_Dbg++;
            consoleLog(line);
        }
    }
    if (tilesOk && (log || changed)) {
        static int s_Sync = 0;
        if (s_Sync < 40) {
            s_Sync++;
            char b[220];
            snprintf(b, sizeof(b),
                "[SYNC] world=%s %ux%u cap=%zu tiles=%zu objs=%zu inv=%zu",
                nameOk ? wname : "?", w, h, (size_t)((end - begin) / stride),
                nT, nO, nI);
            consoleLog(b);
        }
    }
}

// World::LoadFromMem detour — fires exactly when world data finished parsing
// (join + door changes). Captures the ctx pointer on the game thread.
using LoadFromMem_t = void* (*)(void* world, void* buf, unsigned char flag, int arg);
static LoadFromMem_t o_LoadFromMem = nullptr;

static void* hk_LoadFromMem(void* world, void* buf, unsigned char flag, int arg) {
    {
        static int s_Fired = 0;
        if (s_Fired < 3) { s_Fired++; consoleLog("[HOOK] LoadFromMem fired"); }
    }
    if (scanner::fn_GetCtx) {
        uintptr_t ctx = 0;
        typedef uintptr_t (*GetCtx_t)();
        GetCtx_t getCtx = (GetCtx_t)scanner::fn_GetCtx;
        ctx = (uintptr_t)getCtx();
        if (ctx) g_GameCtx.store(ctx, std::memory_order_relaxed);
    }
    void* r = o_LoadFromMem ? o_LoadFromMem(world, buf, flag, arg) : nullptr;
    // world changed — NPC list from the old world is stale
    {
        auto& gs = GameState::instance();
        std::lock_guard<std::mutex> lk(gs.mtx);
        gs.npcs.clear();
    }
    SyncGameCaches(true);
    return r;
}

static void spy_tj(epshook::SavedRegs* r) {
    SpyDump("TJ", r);
    // rdx = direct pointer to the full inbound plaintext C-string
    // (verified: "action|play_sfx\nfile|audio/beep."). Feed the established
    // text pipeline: state updates (spawn/fields) + OnVarlist Lua events.
    char txt[8192];
    size_t n = 0;
    if (SafeReadText((uintptr_t)r->rdx, txt, sizeof(txt), &n)) {
        static int s_TjTextLogged = 0;
        if (s_TjTextLogged < 60) {
            s_TjTextLogged++;
            std::string prev(txt, n < 200 ? n : 200);
            for (auto& c : prev) { if (c == '\n' || c == '\r') c = '|'; }
            consoleLog("[SPY:TJ TEXT] " + prev);
        }
        GameState::instance().parseTextPacket(std::string(txt, n), true);
    }
}
static void spy_disp(epshook::SavedRegs* r) { SpyDump("DISP", r); }

// TLS plaintext outbound writer — dump-verified @0x1419EAEE0 = frame [4] of
// the captured send stack. Sig: fn(ssl rcx, data rdx, len r8d); every
// outbound application record passes through here pre-encryption.
// Suppression: r8d -> 0xFFFFFFFF (negative) takes the fn's own
// `test r8d,r8d; jns` guard -> `xor eax,eax; ret` — never touches SSL.
static void spy_tlsout(epshook::SavedRegs* r) {
    uintptr_t dp = r->rdx;
    uint32_t len = (uint32_t)r->r8;
    if (dp <= 0x10000 || dp >= 0x7FFFFFFFFFFFull || len == 0 || len > 65536) return;

    static int s_tlCal = 0;
    unsigned char head[16] = {};
    size_t rd = len < 16 ? len : 16;
    if (!SafeReadMem(dp, head, rd)) return;

    if (s_tlCal < 6) {
        s_tlCal++;
        char m[240];
        snprintf(m, sizeof(m),
            "[TLSOUT] len=%u hdr=%02X %02X %02X %02X head=%02X %02X %02X %02X %02X %02X %02X %02X",
            len, head[0], head[1], head[2], head[3],
            head[0], head[1], head[2], head[3],
            head[4], head[5], head[6], head[7]);
        consoleLog(m);
    }

    if (GameState::instance().interceptCommand((const char*)dp, (int)len)) {
        consoleLog("[TLSOUT] slash command suppressed (len=" + std::to_string(len) + ")");
        r->r8 = 0xFFFFFFFFULL;         // negative len -> fn returns 0 immediately
        return;
    }

    if (!GameState::instance().parseOutgoing((const char*)dp, (int)len)) {
        consoleLog("[TLSOUT] blocked by Lua hook (len=" + std::to_string(len) + ")");
        r->r8 = 0xFFFFFFFFULL;
        return;
    }
}
static void spy_tankp(epshook::SavedRegs* r) {
    SpyDump("TANK", r);
    // rdx = tank struct; payload = std::string at [rdx+0x20]
    // (ptr@+0x20, size@+0x30 — MSVC SSO layout, size 156 observed).
    // Newline-separated key|val lines (spawn|, netID|, posXY|, name| ...).
    uint64_t p = 0, sz = 0;
    if (SafeReadMem((uintptr_t)r->rdx + 0x20, &p, 8) &&
        SafeReadMem((uintptr_t)r->rdx + 0x30, &sz, 8) &&
        sz >= 4 && sz <= 4096 && p > 0x10000 && p < 0x7FFFFFFFFFFFull) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((void*)p, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            p + sz <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
            std::string payload((const char*)p, (size_t)sz);
            static int s_TkLogged = 0;
            if (s_TkLogged < 40) {
                s_TkLogged++;
                std::string prev = payload.substr(0, 300);
                for (auto& c : prev) { if (c == '\n' || c == '\r' || c == '\0') c = '|'; }
                consoleLog("[SPY:TANK TEXT] " + prev);
            }
            GameState::instance().parseTankUpdate(payload);
        }
    }
}

extern "C" static int DumpReadPage(const void* src, void* dst) {
    __try {
        memcpy(dst, src, 0x1000);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static void DumpGameImage(HMODULE hGame) {
    static bool done = false;
    if (done) return;
    done = true;
    const size_t IMG = 0x4683000;
    FILE* f = fopen("C:\\Users\\LENOVO\\AppData\\Local\\Temp\\opencode\\gtop_dump\\image_mem.bin", "wb");
    if (!f) { consoleLog("[DUMP] open image_mem.bin failed"); return; }
    uintptr_t base = (uintptr_t)hGame;
    std::vector<unsigned char> buf(0x1000);
    size_t off = 0;
    while (off < IMG) {
        if (!DumpReadPage((const void*)(base + off), buf.data()))
            memset(buf.data(), 0, 0x1000);
        fwrite(buf.data(), 1, 0x1000, f);
        off += 0x1000;
    }
    fclose(f);
    char m[160];
    snprintf(m, sizeof(m), "[DUMP] image_mem.bin written base=%p size=0x%zX", hGame, IMG);
    consoleLog(m);
}

void TryInstallNativeHooks() {
    char buf[256];

    // Tank-update handler — resolved by scanner, fires on every in-world update
    if (scanner::fn_ProcessTankUpdatePacket) {
        epshook::Status st = epshook::CreateSpy(
            (void*)scanner::fn_ProcessTankUpdatePacket, spy_ptup);
        snprintf(buf, sizeof(buf), "[SPY] PTUP @0x%llX: %s",
            (unsigned long long)scanner::fn_ProcessTankUpdatePacket,
            epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[SPY] PTUP not resolved — skipping");
    }

    // SendPacket — detour at the real chokepoint (scanner override points
    // at 0x140C464C0): registered slash-commands are dispatched to Lua and
    // never enqueued; text payloads emit OnPacket for lua parity.
    if (scanner::fn_SendPacket) {
        epshook::Status st = epshook::Create((void*)scanner::fn_SendPacket,
                                              (void*)hk_SendPacket,
                                              (void**)&o_SendPacket);
        snprintf(buf, sizeof(buf), "[HOOK] SendPacket @0x%llX: %s",
            (unsigned long long)scanner::fn_SendPacket,
            epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[HOOK] SendPacket not resolved — skipping");
    }

    // World::LoadFromMem — world/tiles/objects/inventory cache sync
    if (scanner::fn_LoadFromMem) {
        epshook::Status st = epshook::Create((void*)scanner::fn_LoadFromMem,
                                              (void*)hk_LoadFromMem,
                                              (void**)&o_LoadFromMem);
        snprintf(buf, sizeof(buf), "[HOOK] LoadFromMem @0x%llX: %s",
            (unsigned long long)scanner::fn_LoadFromMem,
            epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[HOOK] LoadFromMem not resolved — skipping");
    }

    // TextDispatch — tankIDName string xref (game JSON/text-packet parser)
    if (scanner::fn_TextDispatch) {
        epshook::Status st = epshook::CreateSpy(
            (void*)scanner::fn_TextDispatch, spy_tj);
        snprintf(buf, sizeof(buf), "[SPY] TextDispatch @0x%llX: %s",
            (unsigned long long)scanner::fn_TextDispatch,
            epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[SPY] TextDispatch not resolved — skipping");
    }

    // Tank-update field parser — dump-verified address (image_mem.bin),
    // strings: netID|, spawn|, posXY|, mstate|, smstate|, colrect|, name|
    if (scanner::fn_TankParser) {
        epshook::Status st = epshook::CreateSpy(
            (void*)scanner::fn_TankParser, spy_tankp);
        snprintf(buf, sizeof(buf), "[SPY] TANKPARSER @0x%llX: %s",
            (unsigned long long)scanner::fn_TankParser,
            epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[SPY] TANKPARSER not resolved — skipping");
    }

    // TLS outbound plaintext chokepoint — dump-verified address (frame [4]
    // of the send stack): fn(ssl, data, len) with data = framed plaintext.
    // GT-only absolute VA — patching it inside CreativeGrowtopia would write
    // a spy into unrelated code (same class of bug as the disabled DISP spies).
    if (scanner::g_GameImageSize >= 0x1400000ULL) {
        const unsigned long long kTlsOutFn = 0x1419EAEE0ULL;
        epshook::Status st = epshook::CreateSpy((void*)kTlsOutFn, spy_tlsout);
        snprintf(buf, sizeof(buf), "[SPY] TLSOUT @0x%llX: %s",
                 kTlsOutFn, epshook::StatusString(st));
        consoleLog(buf);
    } else {
        consoleLog("[SPY] TLSOUT skipped (non-GT build)");
    }

    // Legacy text-dispatcher candidates — DISABLED: patching these unknown
    // addresses correlates with a ntdll heap-corruption crash ~2min after
    // inject (crash at ntdll+0x15232, no VEH dump, 27 DISP spy hits on a
    // non-pointer RCX). Bisect: remove these, keep only the resolved PTUP
    // spy. Re-enable one at a time to identify the offender.
    static const bool kEnableDispSpies = false;
    if (kEnableDispSpies) {
        void* dispTargets[] = {
            (void*)0x1417E89CB, (void*)0x1417E8360,
            (void*)0x1417C5CC1, (void*)0x1417F1DB0,
        };
        for (void* t : dispTargets) {
            epshook::Status st = epshook::CreateSpy(t, spy_disp);
            snprintf(buf, sizeof(buf), "[SPY] DISP @0x%p: %s", t, epshook::StatusString(st));
            consoleLog(buf);
        }
    } else {
        consoleLog("[SPY] DISP candidates disabled (crash bisect)");
    }
}
#endif // ENABLE_NATIVE_HOOK

void MainThread(HMODULE hModule) {
    while (!GetModuleHandleA("opengl32.dll")) Sleep(100);
    Sleep(500);

    HMODULE hOGL = GetModuleHandleA("opengl32.dll");
    auto p_wglSwapBuffers = (void*)GetProcAddress(hOGL, "wglSwapBuffers");

    AddVectoredExceptionHandler(1, VehHandler);
    consoleLog("[INFO] VEH handler installed");
    epshook::SetLog([](const char* m) { consoleLog(std::string("[EHOOK] ") + m); });

    if (p_wglSwapBuffers) {
        epshook::Status st = epshook::Create(p_wglSwapBuffers, (void*)hk_wglSwapBuffers, (void**)&o_wglSwapBuffers);
        if (st == epshook::OK) {
            consoleLog("[INFO] wglSwapBuffers hook installed");
        } else {
            char buf[160];
            snprintf(buf, sizeof(buf), "[WARN] wglSwapBuffers hook failed: %s", epshook::StatusString(st));
            consoleLog(buf);
        }
    }

    discordrpc::Start([](const char* m) {
        consoleLog(std::string("[RPC] ") + m);
    });

    // System DLL hooks only when GrowPai is NOT loaded.
    // If GrowPai is present, its bridge.json provides all game state —
    // patching ws2_32/bcrypt first makes GrowPai's sigs::init fail and crash.
    // GrowPai finishes sigs::init in ~1.5s; wait up to 15s re-checking so
    // late-loaded GrowPai still wins the race.
    auto isGrowPai = []() -> bool {
        return GetModuleHandleA("Growpai.dll") != nullptr ||
               GetModuleHandleA("GrowPai.dll") != nullptr;
    };
    if (isGrowPai()) {
        consoleLog("[INFO] GrowPai detected — skipping system DLL hooks (bridge provides data)");
    } else {
        bool gotGrowPai = false;
        for (int i = 0; i < 15; i++) {
            Sleep(1000);
            if (isGrowPai()) {
                gotGrowPai = true;
                consoleLog("[INFO] GrowPai loaded during delay — skipping system DLL hooks");
                break;
            }
        }
        if (!gotGrowPai) {
            TryInstallSocketHooks();
            TryInstallTLSHooks();
            TryInstallBCryptHooks();
            consoleLog("[INFO] System DLL hooks ENABLED (no GrowPai after 15s)");
        }
    }

    HMODULE hGame = GetModuleHandleA(NULL);
    if (hGame) {
        scanner::Install(hGame);
        DumpGameImage(hGame);
    }

#if ENABLE_NATIVE_HOOK
    Sleep(1000);
    TryInstallNativeHooks();
#else
    consoleLog("[INFO] Native hook DISABLED (ENABLE_NATIVE_HOOK=0) - packet capture via heap scanner");
#endif

    // Background scanner thread — scans on network activity (rate-limited),
    // forced at least every 5s while in-game; never on game threads
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        DWORD s_lastForce = GetTickCount();
        while (true) {
            bool forced = (GetTickCount() - s_lastForce) > 5000;
            if (InterlockedCompareExchange(&g_HeapScanRequest, 0, 1) == 1 || forced) {
                s_lastForce = GetTickCount();
                ScanHeapForPackets();
            }
            Sleep(100);
        }
        return 0;
    }, nullptr, 0, nullptr);
    consoleLog("[INFO] Background heap scanner started (event-driven, 400ms min interval)");

    // Bridge reader thread — reads GrowPai's bridge.json for game state
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        const char* bridgePath = "C:\\temp\\growpai_bridge.json";
        while (true) {
                // Read and update, then sleep before next read
                HANDLE hFile = CreateFileA(bridgePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hFile == INVALID_HANDLE_VALUE) { Sleep(2000); continue; }
                DWORD fileSize = GetFileSize(hFile, nullptr);
                if (fileSize == 0 || fileSize > 262144) { CloseHandle(hFile); Sleep(2000); continue; }
            char* buf = (char*)malloc(fileSize + 1);
            DWORD read = 0;
            ReadFile(hFile, buf, fileSize, &read, nullptr);
            CloseHandle(hFile);
            buf[read] = '\0';
            std::string json(buf, read);
            free(buf);

            auto& gs = GameState::instance();
            std::lock_guard<std::mutex> lock(gs.mtx);

            // Extract a JSON object's body given a top-level key
            auto extractObject = [&](const std::string& key) -> std::string {
                std::string needle = "\"" + key + "\":";
                size_t pos = json.find(needle);
                if (pos == std::string::npos) return "";
                pos += needle.size();
                while (pos < json.size() && json[pos] == ' ') pos++;
                if (pos >= json.size() || json[pos] != '{') return "";
                int depth = 0;
                size_t start = pos;
                for (; pos < json.size(); pos++) {
                    if (json[pos] == '{') depth++;
                    else if (json[pos] == '}') { depth--; if (depth == 0) return json.substr(start, pos - start + 1); }
                }
                return "";
            };
            auto extractArray = [&](const std::string& key) -> std::string {
                std::string needle = "\"" + key + "\":";
                size_t pos = json.find(needle);
                if (pos == std::string::npos) return "";
                pos += needle.size();
                while (pos < json.size() && json[pos] == ' ') pos++;
                if (pos >= json.size() || json[pos] != '[') return "";
                int depth = 0;
                size_t start = pos;
                for (; pos < json.size(); pos++) {
                    if (json[pos] == '[') depth++;
                    else if (json[pos] == ']') { depth--; if (depth == 0) return json.substr(start, pos - start + 1); }
                }
                return "";
            };

            // Parse localPlayer object
            std::string lpObj = extractObject("localPlayer");
            auto findField = [&](const std::string& obj, const std::string& field) -> std::string {
                std::string needle = "\"" + field + "\"";
                size_t pos = obj.find(needle);
                if (pos == std::string::npos) return "";
                pos = obj.find(':', pos + needle.size());
                if (pos == std::string::npos) return "";
                pos++;
                while (pos < obj.size() && obj[pos] == ' ') pos++;
                if (pos >= obj.size()) return "";
                if (obj[pos] == '"') {
                    size_t end = obj.find('"', pos + 1);
                    if (end == std::string::npos) return "";
                    return obj.substr(pos + 1, end - pos - 1);
                }
                size_t end = pos;
                while (end < obj.size() && obj[end] != ',' && obj[end] != '}' && obj[end] != ']') end++;
                return obj.substr(pos, end - pos);
            };

            std::string name = findField(lpObj, "name");
            std::string world = findField(lpObj, "world");
            std::string gemsStr = findField(lpObj, "gems");
            std::string country = findField(lpObj, "country");
            std::string posX = findField(lpObj, "pos_x");
            std::string posY = findField(lpObj, "pos_y");
            std::string netidStr = findField(lpObj, "netid");
            std::string useridStr = findField(lpObj, "userid");
            std::string tileX = findField(lpObj, "tile_x");
            std::string tileY = findField(lpObj, "tile_y");

            if (!name.empty() && name != "null") {
                gs.localPlayer.name = name;
                if (!world.empty() && world != "null") gs.localPlayer.world = world;
                if (!country.empty() && country != "null") gs.localPlayer.country = country;
                if (!gemsStr.empty()) gs.localPlayer.gems = atoi(gemsStr.c_str());
                if (!posX.empty()) gs.localPlayer.pos_x = (float)atof(posX.c_str());
                if (!posY.empty()) gs.localPlayer.pos_y = (float)atof(posY.c_str());
                if (!netidStr.empty()) gs.localPlayer.netid = atoi(netidStr.c_str());
                if (!useridStr.empty()) gs.localPlayer.userid = atoi(useridStr.c_str());
                if (!tileX.empty()) gs.localPlayer.tile_x = atoi(tileX.c_str());
                if (!tileY.empty()) gs.localPlayer.tile_y = atoi(tileY.c_str());
                consoleLog("[BRIDGE] localPlayer: name=" + gs.localPlayer.name +
                    " gems=" + std::to_string(gs.localPlayer.gems) +
                    " world=" + gs.localPlayer.world +
                    " netid=" + std::to_string(gs.localPlayer.netid));
            }

            // Parse players array
            std::string playersArr = extractArray("players");
            if (!playersArr.empty()) {
                gs.players.clear();
                // Split objects in the array: find {...} groups
                size_t i = 0;
                while (i < playersArr.size()) {
                    if (playersArr[i] == '{') {
                        int depth = 0;
                        size_t start = i;
                        for (; i < playersArr.size(); i++) {
                            if (playersArr[i] == '{') depth++;
                            else if (playersArr[i] == '}') { depth--; if (depth == 0) break; }
                        }
                        if (i >= playersArr.size()) break;
                        std::string pobj = playersArr.substr(start, i - start + 1);
                        PlayerData pd;
                        pd.name = findField(pobj, "name");
                        pd.world = findField(pobj, "world");
                        std::string pnetid = findField(pobj, "netid");
                        std::string puserid = findField(pobj, "userid");
                        std::string pgems = findField(pobj, "gems");
                        std::string ppx = findField(pobj, "pos_x");
                        std::string ppy = findField(pobj, "pos_y");
                        std::string ptx = findField(pobj, "tile_x");
                        std::string pty = findField(pobj, "tile_y");
                        if (!pnetid.empty()) pd.netid = atoi(pnetid.c_str());
                        if (!puserid.empty()) pd.userid = atoi(puserid.c_str());
                        if (!pgems.empty()) pd.gems = atoi(pgems.c_str());
                        if (!ppx.empty()) pd.pos_x = (float)atof(ppx.c_str());
                        if (!ppy.empty()) pd.pos_y = (float)atof(ppy.c_str());
                        if (!ptx.empty()) pd.tile_x = atoi(ptx.c_str());
                        if (!pty.empty()) pd.tile_y = atoi(pty.c_str());
                        if (!pd.name.empty())                     gs.players.push_back(pd);
                        i++;
                    } else i++;
                }
                consoleLog("[BRIDGE] players: " + std::to_string(gs.players.size()));
            }
            std::string invArr = extractArray("inventory");
            if (!invArr.empty()) {
                gs.inventory.clear();
                size_t i = 0;
                while (i < invArr.size()) {
                    if (invArr[i] == '{') {
                        int depth = 0;
                        size_t start = i;
                        for (; i < invArr.size(); i++) {
                            if (invArr[i] == '{') depth++;
                            else if (invArr[i] == '}') { depth--; if (depth == 0) break; }
                        }
                        if (i >= invArr.size()) break;
                        std::string iobj = invArr.substr(start, i - start + 1);
                        InventoryItem it;
                        std::string iid = findField(iobj, "id");
                        std::string icount = findField(iobj, "count");
                        if (!iid.empty()) it.id = atoi(iid.c_str());
                        if (!icount.empty()) it.count = atoi(icount.c_str());
                        if (it.id > 0) gs.inventory.push_back(it);
                        i++;
                    } else i++;
                }
                consoleLog("[BRIDGE] inventory: " + std::to_string(gs.inventory.size()) + " items");
            }

            // Parse objects array
            std::string objArr = extractArray("objects");
            if (!objArr.empty()) {
                gs.objects.clear();
                size_t i = 0;
                while (i < objArr.size()) {
                    if (objArr[i] == '{') {
                        int depth = 0;
                        size_t start = i;
                        for (; i < objArr.size(); i++) {
                            if (objArr[i] == '{') depth++;
                            else if (objArr[i] == '}') { depth--; if (depth == 0) break; }
                        }
                        if (i >= objArr.size()) break;
                        std::string oobj = objArr.substr(start, i - start + 1);
                        WorldObject wo;
                        std::string oid = findField(oobj, "id");
                        std::string ooid = findField(oobj, "oid");
                        std::string opx = findField(oobj, "pos_x");
                        std::string opy = findField(oobj, "pos_y");
                        std::string ocount = findField(oobj, "count");
                        if (!oid.empty()) wo.id = atoi(oid.c_str());
                        if (!ooid.empty()) wo.oid = atoi(ooid.c_str());
                        if (!opx.empty()) wo.pos_x = (float)atof(opx.c_str());
                        if (!opy.empty()) wo.pos_y = (float)atof(opy.c_str());
                        if (!ocount.empty()) wo.count = atoi(ocount.c_str());
                        gs.objects.push_back(wo);
                        i++;
                    } else i++;
                }
                consoleLog("[BRIDGE] objects: " + std::to_string(gs.objects.size()));
            }

            // Ping
            std::string pingStr = findField(json, "ping");
            if (!pingStr.empty()) gs.ping_ms = atoi(pingStr.c_str());
            Sleep(3000);
        }
        return 0;
    }, nullptr, 0, nullptr);
    consoleLog("[INFO] Bridge reader started (reads GrowPai bridge.json)");

    // Watchdog: detect o_* hook originals being zeroed (wild writer).
    // Snapshot at +6s (hooks installed by then), poll for flips, dump the
    // .data page on first flip so we can see how wide the zeroing is.
    std::thread([] {
        Sleep(6000);
        void* snap[10] = { (void*)o_send, (void*)o_recv, (void*)o_sendto, (void*)o_recvfrom,
                           (void*)o_WSASend, (void*)o_WSARecv, (void*)o_WSARecvFrom,
                           (void*)o_WSASendTo, (void*)o_connect, (void*)o_WSASocketW };
        const char* names[10] = { "o_send", "o_recv", "o_sendto", "o_recvfrom", "o_WSASend",
                                  "o_WSARecv", "o_WSARecvFrom", "o_WSASendTo", "o_connect",
                                  "o_WSASocketW" };
        char m[240];
        snprintf(m, sizeof(m),
                 "[WATCHDOG] snapshot o_send=0x%p o_recv=0x%p o_WSASend=0x%p o_WSARecv=0x%p o_connect=0x%p",
                 snap[0], snap[1], snap[4], snap[5], snap[8]);
        consoleLog(m);
        int nullAtStart = 0;
        for (int i = 0; i < 10; i++) if (!snap[i]) nullAtStart++;
        if (nullAtStart) {
            snprintf(m, sizeof(m), "[WATCHDOG] %d originals already NULL at snapshot (never set?)", nullAtStart);
            consoleLog(m);
        }
        bool fired = false;
        while (!fired) {
            void* cur[10] = { (void*)o_send, (void*)o_recv, (void*)o_sendto, (void*)o_recvfrom,
                              (void*)o_WSASend, (void*)o_WSARecv, (void*)o_WSARecvFrom,
                              (void*)o_WSASendTo, (void*)o_connect, (void*)o_WSASocketW };
            for (int i = 0; i < 10; i++) {
                if (snap[i] && !cur[i]) {
                    fired = true;
                    snprintf(m, sizeof(m), "[WATCHDOG] %s FLIPPED TO NULL (was 0x%p)!",
                             names[i], snap[i]);
                    consoleLog(m);
                    break;
                }
            }
            if (fired) {
                unsigned char page[4096];
                if (ReadDataPageSafe(page, 4096) == 4096) {
                    for (int row = 0; row < 4096; row += 128) {
                        char line[440];
                        int pos = snprintf(line, sizeof(line), "[WATCHDOG DATA +0x%03X]", row);
                        for (int b = 0; b < 128 && pos < 420; b++)
                            pos += snprintf(line + pos, sizeof(line) - pos, " %02X", page[row + b]);
                        consoleLog(line);
                    }
                }
            }
            Sleep(250);
        }
        Sleep(3600000);
    }).detach();

    auto t0 = std::chrono::steady_clock::now();

    while (true) {
        Sleep(100);
        auto now = std::chrono::steady_clock::now();
        g_currentTime = std::chrono::duration<float>(now - t0).count();
    }

    epshook::RemoveAll();
    FreeLibraryAndExitThread(hModule, 0);
}

// ── DLL Entry ────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        SetUnhandledExceptionFilter(UnhandledFilter);
        HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
