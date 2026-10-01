#include "scanner.h"
#include "hook.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>

extern void debugLog(const std::string& msg);
extern void consoleLog(const std::string& msg);

extern volatile LONG g_SafeReadProbe;

namespace scanner {

    static bool g_Installed = false;

    // SEH-safe raw read: returns bytes copied, 0 if address is unreadable.
    // Suppresses VEH crash logging while probing (g_SafeReadProbe).
    extern "C" static int SafeReadBytes(const void* src, void* dst, int n) {
        InterlockedIncrement(&g_SafeReadProbe);
        int got = 0;
        __try {
            memcpy(dst, src, n);
            got = n;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            got = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return got;
    }

    uintptr_t fn_ProcessTankUpdatePacket = 0;
    uintptr_t fn_SendPacket = 0;
    uintptr_t fn_GetGameLogic = 0;
    uintptr_t fn_TextDispatch = 0;
    uintptr_t fn_TankParser = 0;
    uintptr_t fn_LoadFromMem = 0;
    uintptr_t fn_GetCtx = 0;
    uintptr_t g_GameBase = 0;
    size_t g_GameImageSize = 0;

    bool HooksInstalled() { return g_Installed; }

    static FILE* g_scanLogFile = nullptr;

    static void Log(const char* msg) {
        debugLog(std::string("[SCAN] ") + msg);
        consoleLog(std::string("[SCAN] ") + msg);
        if (!g_scanLogFile) {
            CreateDirectoryA("C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\package-scanner-output\\scan log", nullptr);
            g_scanLogFile = fopen("C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\package-scanner-output\\scan log\\scan.txt", "w");
        }
        if (g_scanLogFile) {
            fprintf(g_scanLogFile, "%s\n", msg);
            fflush(g_scanLogFile);
        }
    }

    static void LogHex(const char* label, uintptr_t addr, int len) {
        BYTE raw[64];
        int n = len < 64 ? len : 64;
        int got = SafeReadBytes((const void*)addr, raw, n);
        std::string hex;
        if (got <= 0) {
            hex = "<unreadable>";
        } else {
            for (int i = 0; i < got; i++) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", raw[i]);
                hex += buf;
            }
        }
        Log((std::string(label) + ": " + hex).c_str());
    }

    static bool IsExecutable(DWORD prot) {
        return (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    static bool IsReadable(DWORD prot) {
        return (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    struct MemRegion { uintptr_t start; size_t size; DWORD protect; };

    // SEH-isolated pattern search: catches races where the game unmaps a
    // region between our VirtualQuery enumeration and these byte reads.
    // No C++ objects inside __try (C2712). Suppresses VEH dump while probing.
    extern "C" static int SafeFindPattern(uintptr_t start, size_t size, const int* pat, int patLen, uintptr_t* outAddr) {
        if (!pat || patLen <= 0 || size < (size_t)patLen) return 0;
        InterlockedIncrement(&g_SafeReadProbe);
        int found = 0;
        __try {
            uintptr_t end = start + size - patLen;
            for (uintptr_t a = start; a <= end; a++) {
                int j = 0;
                for (; j < patLen; j++) {
                    if (pat[j] != -1 && *(volatile BYTE*)(a + j) != (BYTE)pat[j]) break;
                }
                if (j == patLen) { *outAddr = a; found = 1; break; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return found;
    }

    static std::vector<int> ParsePattern(const char* pattern) {
        std::vector<int> bytes;
        const char* p = pattern;
        while (*p) {
            if (*p == ' ') { p++; continue; }
            if (*p == '?') {
                bytes.push_back(-1);
                p++;
                if (*p == '?') p++;
            } else {
                bytes.push_back((int)strtoul(p, (char**)&p, 16));
            }
        }
        return bytes;
    }

    static bool FindPatternInRegion(uintptr_t start, size_t size, const char* pattern, uintptr_t& outAddr) {
        std::vector<int> bytes = ParsePattern(pattern);
        if (bytes.empty()) return false;
        uintptr_t found = 0;
        if (SafeFindPattern(start, size, bytes.data(), (int)bytes.size(), &found)) {
            outAddr = found;
            return true;
        }
        return false;
    }

    static uintptr_t FindFuncStart(uintptr_t addr) {
        uintptr_t result = addr;
        uintptr_t lo = (addr > 0x5000) ? addr - 0x5000 : 0x10000;
        if (lo < 0x10000) lo = 0x10000;
        __try {
            for (uintptr_t a = addr; ; a--) {
                BYTE b[4] = {};
                if (SafeReadBytes((const void*)a, b, 4) < 4) break;
                if (b[0] == 0xC3 || b[0] == 0xCC) { result = a + 1; break; }
                if (b[0] == 0x55) { result = a; break; }
                if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) { result = a; break; }
                if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) { result = a; break; }
                if (b[0] == 0x40 && b[1] == 0x53 && b[2] == 0x48 && b[3] == 0x83) { result = a; break; }
                if (b[0] == 0x48 && b[1] == 0x89 && (b[2] & 0x38) == 0x18) { result = a; break; }
                if (a <= lo) break;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return result;
    }

    static bool LooksLikeFuncStart(uintptr_t addr) {
        BYTE p[4] = {};
        if (SafeReadBytes((const void*)addr, p, 4) < 4) return false;
        if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) return true;
        if (p[0] == 0x48 && p[1] == 0x89 && (p[2] & 0x38) == 0x18) return true;
        if (p[0] == 0x40 && p[1] == 0x53 && p[2] == 0x48) return true;
        if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return true;
        if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return true;
        if (p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89) return true;
        if (p[0] == 0x53) return true;
        return false;
    }

    // SEH-isolated scanners (no C++ objects): region may be unmapped mid-scan.
    // Walks all matches in the region; verifies resolved call targets with
    // LooksLikeFuncStart (itself SEH-safe).
    extern "C" static int SafeFindCallTarget(uintptr_t start, size_t size, const int* pat, int patLen, int dispRel, uintptr_t* outTarget) {
        if (!pat || patLen <= 0 || size < (size_t)patLen) return 0;
        InterlockedIncrement(&g_SafeReadProbe);
        int found = 0;
        __try {
            uintptr_t regionEnd = start + size;
            uintptr_t cur = start;
            while (cur <= regionEnd - patLen) {
                uintptr_t hit = 0;
                for (uintptr_t a = cur; a <= regionEnd - patLen; a++) {
                    int j = 0;
                    for (; j < patLen; j++) {
                        if (pat[j] != -1 && *(volatile BYTE*)(a + j) != (BYTE)pat[j]) break;
                    }
                    if (j == patLen) { hit = a; break; }
                }
                if (!hit) break;
                int32_t disp = *(int32_t*)(hit + dispRel);
                uintptr_t target = hit + dispRel + 4 + disp;
                if (LooksLikeFuncStart(target)) { *outTarget = target; found = 1; break; }
                cur = hit + 1;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return found;
    }

    extern "C" static int SafeFindGenericSP(uintptr_t start, size_t size, uintptr_t skipFunc, uintptr_t* outTarget) {
        if (size < 9) return 0;
        InterlockedIncrement(&g_SafeReadProbe);
        int found = 0;
        __try {
            uintptr_t searchEnd = start + size - 9;
            for (uintptr_t sa = start; sa <= searchEnd; sa++) {
                volatile BYTE* pp = (volatile BYTE*)sa;
                if (pp[0] == 0x02 && pp[1] == 0x00 && pp[2] == 0x00 && pp[3] == 0x00 && pp[4] == 0xE8) {
                    int32_t disp = *(int32_t*)(pp + 5);
                    uintptr_t callAddr = sa + 4;
                    uintptr_t target = callAddr + 5 + disp;
                    if (target != skipFunc && LooksLikeFuncStart(target)) {
                        *outTarget = target;
                        found = 1;
                        break;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return found;
    }

    extern "C" static int SafeFindString(uintptr_t start, size_t size, const char* s, int slen, uintptr_t* outHit) {
        if (!s || slen <= 0 || size < (size_t)slen) return 0;
        InterlockedIncrement(&g_SafeReadProbe);
        int found = 0;
        __try {
            uintptr_t end = start + size - slen;
            for (uintptr_t a = start; a <= end; a++) {
                if (memcmp((const void*)a, s, slen) == 0) { *outHit = a; found = 1; break; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return found;
    }

    extern "C" static int SafeFindLeaXref(uintptr_t start, size_t size, uintptr_t strAddr, uintptr_t* outEa) {
        if (size < 7) return 0;
        InterlockedIncrement(&g_SafeReadProbe);
        int found = 0;
        __try {
            uintptr_t end = start + size - 7;
            for (uintptr_t ea = start; ea <= end; ea++) {
                volatile BYTE* pp = (volatile BYTE*)ea;
                if (pp[0] == 0x48 && pp[1] == 0x8D && (pp[2] & 0xC7) == 0x05) {
                    int32_t disp = *(int32_t*)(pp + 3);
                    if (ea + 7 + disp == strAddr) { *outEa = ea; found = 1; break; }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = 0;
        }
        InterlockedDecrement(&g_SafeReadProbe);
        return found;
    }

    bool Install(HMODULE gameModule) {
        if (g_Installed) return true;
        if (!gameModule) return false;

        uintptr_t base = (uintptr_t)gameModule;
        g_GameBase = base;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)gameModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)gameModule + dos->e_lfanew);
        g_GameImageSize = nt->OptionalHeader.SizeOfImage;

        char buf[256];
        snprintf(buf, sizeof(buf), "Base: 0x%llX, Image: 0x%llX", (unsigned long long)base, (unsigned long long)g_GameImageSize);
        Log(buf);

        std::vector<MemRegion> allExecRegions;
        std::vector<MemRegion> allReadRegions;

        uintptr_t addr = 0;
        while (addr < 0x7FFFFFFFFFFFFFFF) {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
            if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 && mbi.RegionSize < 0x10000000) {
                if (IsExecutable(mbi.Protect))
                    allExecRegions.push_back({ (uintptr_t)mbi.BaseAddress, mbi.RegionSize, mbi.Protect });
                if (IsReadable(mbi.Protect) && !IsExecutable(mbi.Protect))
                    allReadRegions.push_back({ (uintptr_t)mbi.BaseAddress, mbi.RegionSize, mbi.Protect });
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (addr <= (uintptr_t)mbi.BaseAddress) break;
        }

        snprintf(buf, sizeof(buf), "Exec regions: %d, Read regions: %d", (int)allExecRegions.size(), (int)allReadRegions.size());
        Log(buf);

        for (auto& r : allExecRegions) {
            snprintf(buf, sizeof(buf), "  Exec: 0x%llX size=0x%llX prot=0x%X",
                (unsigned long long)r.start, (unsigned long long)r.size, r.protect);
            Log(buf);
        }

        Log("=== PATTERN SCAN (ALL MEMORY) ===");

        // Find PTUP by looking for ALL matches and picking the LAST one
        {
            uintptr_t lastFound = 0;
            for (auto& r : allExecRegions) {
                uintptr_t found = 0;
                if (FindPatternInRegion(r.start, r.size, "83 78 04 71 75", found)) {
                    uintptr_t funcStart = FindFuncStart(found);
                    char buf2[256];
                    snprintf(buf2, sizeof(buf2), "PTUP candidate: 0x%llX (region 0x%llX)",
                        (unsigned long long)funcStart, (unsigned long long)r.start);
                    Log(buf2);
                    lastFound = funcStart;
                }
            }
            if (lastFound) {
                fn_ProcessTankUpdatePacket = lastFound;
                snprintf(buf, sizeof(buf), "ProcessTankUpdatePacket: 0x%llX", (unsigned long long)fn_ProcessTankUpdatePacket);
                Log(buf);
                LogHex("  PTUP", fn_ProcessTankUpdatePacket, 32);
            }
        }

        // String xref: find "OnSpawn" in read regions, trace LEA xrefs in exec regions
        {
            Log("String xref scan for PTUP...");
            const char* targetStr = "OnSpawn";
            int targetLen = (int)strlen(targetStr);
            int xrefHits = 0;
            for (auto& r : allReadRegions) {
                if (xrefHits >= 64) break;
                // game image only — heap copies of the string (lua registry,
                // event tables) have no static LEA and each one used to cost
                // a full walk of every exec region (minutes of stall)
                if (r.start + r.size <= base || r.start >= base + g_GameImageSize) continue;
                if (r.size < (size_t)targetLen) continue;
                uintptr_t bound = r.start + r.size;
                uintptr_t cur = r.start;
                uintptr_t sa = 0;
                while (xrefHits < 64 && cur <= bound - targetLen &&
                       SafeFindString(cur, bound - cur, targetStr, targetLen, &sa)) {
                    xrefHits++;
                    char buf2[256];
                    snprintf(buf2, sizeof(buf2), "Found '%s' at 0x%llX", targetStr, (unsigned long long)sa);
                    Log(buf2);
                    // Search exec regions for LEA instructions referencing this string
                    for (auto& er : allExecRegions) {
                        if (er.start + er.size <= base || er.start >= base + g_GameImageSize) continue;
                        uintptr_t ea = 0;
                        if (SafeFindLeaXref(er.start, er.size, sa, &ea)) {
                            uintptr_t funcStart = FindFuncStart(ea);
                            snprintf(buf2, sizeof(buf2), "LEA xref to '%s' at 0x%llX (func 0x%llX)",
                                targetStr, (unsigned long long)ea, (unsigned long long)funcStart);
                            Log(buf2);
                            // Use string xref result instead of pattern result
                            fn_ProcessTankUpdatePacket = funcStart;
                            break;
                        }
                    }
                    if (fn_ProcessTankUpdatePacket) break;
                    cur = sa + 1;
                }
                if (fn_ProcessTankUpdatePacket) break;
            }
            if (fn_ProcessTankUpdatePacket) {
                snprintf(buf, sizeof(buf), "PTUP (string xref): 0x%llX", (unsigned long long)fn_ProcessTankUpdatePacket);
                Log(buf);
                LogHex("  PTUP", fn_ProcessTankUpdatePacket, 32);
            }
        }

        {
            const char* spPatterns[] = {
                "02 00 00 00 E8 ?? ?? ?? ?? 90 48 8D 4C 24 50",
                "02 00 00 00 E8 ?? ?? ?? ?? 90 48",
                "02 00 00 00 E8 ?? ?? ?? ?? 8B",
            };

            for (auto& pat : spPatterns) {
                if (fn_SendPacket) break;
                std::vector<int> pb = ParsePattern(pat);
                if (pb.empty()) continue;
                uintptr_t target = 0;
                for (auto& r : allExecRegions) {
                    if (SafeFindCallTarget(r.start, r.size, pb.data(), (int)pb.size(), 5, &target)) {
                        fn_SendPacket = target;
                        snprintf(buf, sizeof(buf), "SendPacket: 0x%llX", (unsigned long long)fn_SendPacket);
                        Log(buf);
                        LogHex("  SP", fn_SendPacket, 32);
                        break;
                    }
                }
            }

            if (!fn_SendPacket) {
                for (auto& r : allExecRegions) {
                    uintptr_t target = 0;
                    if (SafeFindGenericSP(r.start, r.size, fn_ProcessTankUpdatePacket, &target)) {
                        fn_SendPacket = target;
                        snprintf(buf, sizeof(buf), "SendPacket (generic): 0x%llX", (unsigned long long)fn_SendPacket);
                        Log(buf);
                        LogHex("  SP", fn_SendPacket, 32);
                        break;
                    }
                }
            }

            if (!fn_SendPacket) Log("SendPacket: NOT RESOLVED");
        }

        // Static call-graph: who actually calls SendPacket / the PTUP candidate?
        {
            auto dumpCallers = [&](uintptr_t target, const char* name) {
                if (!target) return;
                int found = 0;
                for (auto& r : allExecRegions) {
                    if (found >= 12) break;
                    if (r.size < 8) continue;
                    std::vector<unsigned char> buf2(r.size);
                    int got = SafeReadBytes((const void*)r.start, buf2.data(), (int)r.size);
                    if (got < 8) continue;
                    for (int i = 0; i < got - 5; i++) {
                        if (buf2[i] != 0xE8) continue;
                        int32_t rel;
                        memcpy(&rel, &buf2[i + 1], 4);
                        uintptr_t p = r.start + i;
                        uintptr_t dest = p + 5 + (intptr_t)rel;
                        if (dest != target) continue;
                        uintptr_t fnStart = FindFuncStart(p);
                        snprintf(buf, sizeof(buf), "CALLS %s at 0x%llX (caller fn 0x%llX)",
                                 name, (unsigned long long)p, (unsigned long long)fnStart);
                        Log(buf);
                        LogHex("  ctx", p, 96);
                        found++;
                        i += 4;
                        if (found >= 12) break;
                    }
                }
                if (!found) {
                    snprintf(buf, sizeof(buf), "CALLS %s: NONE — function has no static callers (dead code)",
                             name);
                    Log(buf);
                }
            };
            ScanRecvWrapper();
            dumpCallers(fn_SendPacket, "SendPacket");
            dumpCallers(fn_ProcessTankUpdatePacket, "PTUP");
            if (fn_RecvWrapper) dumpCallers(fn_RecvWrapper, "RecvWrapper");
        }

        // Extra string xrefs — log candidate functions, do NOT spy blindly.
        // Skip our own module (heap markers live in EpsHax.dll .data).
        {
            uintptr_t selfBase = (uintptr_t)GetModuleHandleA("EpsHax.dll");
            const char* altStrs[] = { "tankIDName", "OnMoney", "action|", "on_varlist",
                                      "set_field_init", "join_request" };
            for (auto& s : altStrs) {
                int slen = (int)strlen(s);
                uintptr_t sa = 0;
                int xrefCount = 0;
                for (auto& r : allReadRegions) {
                    if (xrefCount >= 8) break;
                    if (r.start + r.size <= base || r.start >= base + g_GameImageSize) continue;
                    if (r.size < (size_t)slen) continue;
                    uintptr_t bound = r.start + r.size;
                    uintptr_t cur = r.start;
                    while (xrefCount < 8 && cur <= bound - slen &&
                           SafeFindString(cur, bound - cur, s, slen, &sa)) {
                        bool inSelf = selfBase && sa >= selfBase && sa < selfBase + 0x800000;
                        if (!inSelf) {
                            for (auto& er : allExecRegions) {
                                if (er.start + er.size <= base || er.start >= base + g_GameImageSize) continue;
                                uintptr_t ea = 0;
                                if (SafeFindLeaXref(er.start, er.size, sa, &ea)) {
                                    uintptr_t fnStart = FindFuncStart(ea);
                                    snprintf(buf, sizeof(buf),
                                             "XREF '%s' str@0x%llX lea@0x%llX fn=0x%llX",
                                             s, (unsigned long long)sa, (unsigned long long)ea,
                                             (unsigned long long)fnStart);
                                    Log(buf);
                                    if (strcmp(s, "tankIDName") == 0 && !fn_TextDispatch) {
                                        fn_TextDispatch = fnStart;
                                    }
                                    xrefCount++;
                                    break;
                                }
                            }
                        }
                        cur = sa + 1;
                    }
                }
                if (!xrefCount) {
                    snprintf(buf, sizeof(buf), "XREF '%s': not found", s);
                    Log(buf);
                }
            }
            if (fn_TextDispatch) {
                int found = 0;
                for (auto& r : allExecRegions) {
                    if (found >= 8) break;
                    if (r.size < 8) continue;
                    std::vector<unsigned char> cb(r.size);
                    int got = SafeReadBytes((const void*)r.start, cb.data(), (int)r.size);
                    if (got < 8) continue;
                    for (int i = 0; i < got - 5; i++) {
                        if (cb[i] != 0xE8) continue;
                        int32_t rel;
                        memcpy(&rel, &cb[i + 1], 4);
                        uintptr_t p = r.start + i;
                        if (p + 5 + (intptr_t)rel != fn_TextDispatch) continue;
                        snprintf(buf, sizeof(buf),
                                 "CALLS TextDispatch at 0x%llX (caller fn 0x%llX)",
                                 (unsigned long long)p, (unsigned long long)FindFuncStart(p));
                        Log(buf);
                        LogHex("  ctx", p, 96);
                        found++;
                        i += 4;
                    }
                }
                if (!found) Log("CALLS TextDispatch: NONE — static dead?");
            }
        }

        {
            const char* glPatterns[] = {
                "E8 ?? ?? ?? ?? 48 8D ? ? ? ? ? E8 ?? ?? ?? ?? 48 8B",
                "48 8B C4 4C 89 48 20 4C 89 40 18 48 89 50 10 53 56 57 41 56 48 83 EC 38 4D 8B F1 49 8B D8 48 8B",
            };

            for (auto& pat : glPatterns) {
                if (fn_GetGameLogic) break;
                std::vector<int> pb = ParsePattern(pat);
                if (pb.empty()) continue;
                if (pat[0] == 'E') {
                    uintptr_t target = 0;
                    for (auto& r : allExecRegions) {
                        if (SafeFindCallTarget(r.start, r.size, pb.data(), (int)pb.size(), 1, &target)) {
                            fn_GetGameLogic = target;
                            break;
                        }
                    }
                } else {
                    uintptr_t found = 0;
                    for (auto& r : allExecRegions) {
                        if (FindPatternInRegion(r.start, r.size, pat, found)) {
                            fn_GetGameLogic = found;
                            break;
                        }
                    }
                }
                if (fn_GetGameLogic) {
                    snprintf(buf, sizeof(buf), "GetGameLogic: 0x%llX", (unsigned long long)fn_GetGameLogic);
                    Log(buf);
                    LogHex("  GL", fn_GetGameLogic, 32);
                    break;
                }
            }

            if (!fn_GetGameLogic) Log("GetGameLogic: NOT RESOLVED");
        }

        // ── Ground truth offsets (provenance corrected 2026-10-01) ──
        // The 0x140... absolute VAs below were derived from the OFFICIAL
        // Growtopia.exe (SizeOfImage 0x4683000, DYNAMIC_BASE off → loads at
        // 0x140000000 fixed, .text covers them). CreativeGrowtopia.exe is a
        // different, much smaller build (SizeOfImage 0x438000, ASLR on) where
        // those addresses do not exist — for that build we use offsets
        // re-derived from a live Creative memory dump (2026-10-01):
        //   text/action handler   base+0xC6790 ("bad net game message",
        //     "Unknown server message: %s"; 'action|' lea at +0xC67B0 inside
        //     it; rcx=ctx, rdx=plaintext text) — spy_tj contract unchanged
        //   type-4 gamepacket fn  base+0xCB030 (rcx=ctx, rdx=GameUpdatePacket;
        //     world decompress / join / OnVariant live inside) — spy_ptup
        //     falls back to this contract when the Growtopia one misreads
        //   fn_SendPacket / fn_LoadFromMem / fn_GetCtx: not located in the
        //   Creative build yet — left 0 (callers all guard on 0), ctx comes
        //   from the manual *(*(base+0x3AC438)+0xA98) chain in
        //   SyncGameCaches, world resync from world-pointer change detect.
        if (g_GameImageSize >= 0x1400000ULL) {
            // official Growtopia.exe layout (absolute, ASLR off)
            fn_ProcessTankUpdatePacket = 0x140A166B0ULL;
            fn_TextDispatch = 0x140B401A0ULL;
            fn_TankParser = 0x140B3E690ULL;
            fn_SendPacket = 0x140C464C0ULL;
            fn_LoadFromMem = 0x14145F590ULL;
            fn_GetCtx = 0x140B2D9D0ULL;
            Log("[SCAN] using Growtopia.exe ground-truth addresses");
        } else {
            // CreativeGrowtopia build — dump-verified RVAs rebased to ASLR base
            fn_TextDispatch = base + 0xC6790ULL;
            fn_ProcessTankUpdatePacket = base + 0xCB030ULL;
            fn_TankParser = 0;
            fn_SendPacket = 0;
            fn_LoadFromMem = 0;
            fn_GetCtx = 0;
            Log("[SCAN] using Creative-dump addresses (SendPacket unresolved)");
        }

        g_Installed = true;
        Log("=== RESOLVED FUNCTIONS ===");
        snprintf(buf, sizeof(buf), "  PTUP = 0x%llX", (unsigned long long)fn_ProcessTankUpdatePacket);
        Log(buf);
        snprintf(buf, sizeof(buf), "  SendPacket = 0x%llX", (unsigned long long)fn_SendPacket);
        Log(buf);
        snprintf(buf, sizeof(buf), "  GetGameLogic = 0x%llX", (unsigned long long)fn_GetGameLogic);
        Log(buf);
        Log("=== SCAN COMPLETE ===");
        if (g_scanLogFile) { fclose(g_scanLogFile); g_scanLogFile = nullptr; }

        return true;
    }

    // SEH-safe wrappers (no C++ objects - C only)
    extern "C" {
        static void* g_pfnGetGameLogic = nullptr;
        static void* g_pfnSendPacket = nullptr;
        static char g_sendStrBuf[32] = {};
        static size_t g_sendLen = 0;
        static int g_sendType = 0;

        static void* __cdecl CallGL_Internal() {
            typedef void*(__cdecl* fn_t)();
            return ((fn_t)g_pfnGetGameLogic)();
        }

        static void __fastcall CallSP_Internal() {
            typedef void(__fastcall* fn_t)(int, void*, void*);
            ((fn_t)g_pfnSendPacket)(g_sendType, g_sendStrBuf, nullptr);
        }

        static void* DoCallGetGameLogic() {
            void* result = nullptr;
            __try {
                result = CallGL_Internal();
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
            return result;
        }

        static void DoCallSendPacket() {
            __try {
                CallSP_Internal();
            } __except(EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }

    void* CallGetGameLogic() {
        if (!fn_GetGameLogic) return nullptr;
        g_pfnGetGameLogic = (void*)fn_GetGameLogic;
        void* result = DoCallGetGameLogic();
        if (!result) debugLog("[SCAN] GetGameLogic call crashed");
        return result;
    }

    void CallSendPacket(int type, const char* text) {
        if (!fn_SendPacket || !text) return;

        memset(g_sendStrBuf, 0, 32);
        g_sendLen = strlen(text);
        if (g_sendLen < 16) {
            memcpy(g_sendStrBuf, text, g_sendLen);
            g_sendStrBuf[g_sendLen] = '\0';
            *(size_t*)(g_sendStrBuf + 16) = g_sendLen;
            *(size_t*)(g_sendStrBuf + 24) = 15;
        } else {
            char* heap = _strdup(text);
            *(char**)g_sendStrBuf = heap;
            *(size_t*)(g_sendStrBuf + 16) = g_sendLen;
            *(size_t*)(g_sendStrBuf + 24) = g_sendLen;
        }

        g_pfnSendPacket = (void*)fn_SendPacket;
        g_sendType = type;

        DoCallSendPacket();

        if (g_sendLen >= 16 && *(char**)g_sendStrBuf) {
            free(*(char**)g_sendStrBuf);
        }
        memset(g_sendStrBuf, 0, 32);
    }

    void CallSendPacketBin(int type, const void* data, size_t len) {
        if (!fn_SendPacket || !data) return;

        memset(g_sendStrBuf, 0, 32);
        g_sendLen = len;
        if (g_sendLen < 16) {
            memcpy(g_sendStrBuf, data, g_sendLen);
            *(size_t*)(g_sendStrBuf + 16) = g_sendLen;
            *(size_t*)(g_sendStrBuf + 24) = 15;
        } else {
            char* heap = (char*)malloc(g_sendLen);
            if (!heap) return;
            memcpy(heap, data, g_sendLen);
            *(char**)g_sendStrBuf = heap;
            *(size_t*)(g_sendStrBuf + 16) = g_sendLen;
            *(size_t*)(g_sendStrBuf + 24) = g_sendLen;
        }

        g_pfnSendPacket = (void*)fn_SendPacket;
        g_sendType = type;

        DoCallSendPacket();

        if (g_sendLen >= 16 && *(char**)g_sendStrBuf) {
            free(*(char**)g_sendStrBuf);
        }
        memset(g_sendStrBuf, 0, 32);
    }
}

uintptr_t scanner::fn_RecvWrapper = 0;

void scanner::ScanRecvWrapper() {
    uintptr_t recvRetAddr = 0x1419EBD08;
    char buf[256];

    uintptr_t funcStart = FindFuncStart(recvRetAddr);
    if (funcStart) {
        snprintf(buf, sizeof(buf), "[SCAN] Recv wrapper: 0x%p (from ret addr 0x%p)", (void*)funcStart, (void*)recvRetAddr);
        consoleLog(buf);

        BYTE codeBytes[32] = {};
        int got = SafeReadBytes((const void*)funcStart, codeBytes, 32);
        char hex[128] = {};
        int pos = 0;
        for (int i = 0; i < got && pos < 120; i++) {
            pos += snprintf(hex + pos, 128 - pos, "%02X ", codeBytes[i]);
        }
        snprintf(buf, sizeof(buf), "[SCAN] RW bytes: %s", hex);
        consoleLog(buf);

        fn_RecvWrapper = funcStart;
    } else {
        snprintf(buf, sizeof(buf), "[SCAN] Could not find recv wrapper start from 0x%p", (void*)recvRetAddr);
        consoleLog(buf);
    }
}
