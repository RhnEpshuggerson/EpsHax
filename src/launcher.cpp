// EpsHaxLauncher — GUI launcher for Growtopia / CreativeGrowtopia.
// Tabs: Main (target, Play, Inject), Scripts (EpsScript manager), Logs.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ── ids ────────────────────────────────────────────────────────────────
#define IDC_TAB          100
#define IDC_RADIO_GT     110
#define IDC_RADIO_CG     111
#define IDC_GAMEPATH     112
#define IDC_DLLPATH      113
#define IDC_BTN_PLAY     120
#define IDC_BTN_INJECT   121
#define IDC_BTN_FOLDER   122
#define IDC_STATIC_AUTO  124
#define IDC_LIST         130
#define IDC_BTN_RUN      131
#define IDC_BTN_REFRESH  132
#define IDC_BTN_NEW      133
#define IDC_BTN_EDIT     134
#define IDC_BTN_DELETE   135
#define IDC_BTN_FOLDER2  136
#define IDC_CHK_AUTO     137
#define IDC_EDIT_LOG     140
#define IDC_BTN_LOGREF   141
#define IDC_STATUSBAR    150

#define WM_APP_LOG    (WM_APP + 1)  // lParam = wchar_t* event (owned, free it)
#define WM_APP_STATUS (WM_APP + 2)  // lParam = wchar_t* status (owned)
#define WM_APP_DONE   (WM_APP + 3)  // lParam = wchar_t* final status (owned)

// ── targets ────────────────────────────────────────────────────────────
struct TargetInfo { int id; const wchar_t* label; const wchar_t* exeRel; const wchar_t* proc; };
static const TargetInfo kTargets[2] = {
    { 0, L"Growtopia",        L"\\Growtopia\\Growtopia.exe",         L"Growtopia.exe" },
    { 1, L"Creative Growtopia", L"\\CreativeGrowtopia\\CreativeGrowtopia.exe", L"CreativeGrowtopia.exe" },
};
static int g_target = 0;

// ── globals ────────────────────────────────────────────────────────────
static HWND g_hWnd, g_tab, g_pages[3], g_status;
static HWND g_btnPlay, g_btnInject, g_btnRun, g_chkAuto;
static HWND g_list, g_editLog;
static HWND g_p0, g_radioGT, g_radioCG, g_gamePath, g_dllEdit, g_autoCombo;
static HFONT g_font, g_mono;
static volatile LONG g_busy = 0;
static bool g_foreOnStart = false;
static std::thread g_worker;
static std::vector<std::wstring> g_events;      // newest first, cap 60
static std::wstring g_auto[2];                  // auto-run script per target
static std::wstring g_lastSel[2];
static int g_page = 0;

static void FillAutoCombo();
static bool ProbeWorld(HANDLE h, DWORD pid, std::wstring* out);
static bool ClickGamePlay(DWORD pid);
static void SyncAutoCheck();
static std::wstring Utf8OrAcpToWide(const char* p, int n);

// ── small helpers ──────────────────────────────────────────────────────
static std::wstring GetLocalAppData() {
    wchar_t p[MAX_PATH]{};
    SHGetFolderPathW(nullptr, 0x001C /*CSIDL_LOCAL_APPDATA*/, nullptr, 0, p);
    return p;
}
static std::wstring GameDir()      { return GetLocalAppData() + kTargets[g_target].exeRel; } // parent of exe
static std::wstring ExePath()      { return GameDir(); }
static std::wstring ScriptDir()    { return GetLocalAppData() +
    (g_target == 0 ? L"\\Growtopia\\EpsScript" : L"\\CreativeGrowtopia\\EpsScript"); }
static std::wstring IniPath() {
    std::wstring d = GetLocalAppData() + L"\\EpsHax";
    CreateDirectoryW(d.c_str(), nullptr);
    return d + L"\\launcher.ini";
}
static std::wstring DirOf(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(0, p);
}
static void PostStr(UINT msg, const std::wstring& s) {
    if (!g_hWnd) return;
    wchar_t* p = _wcsdup(s.c_str());
    if (!p) return;
    if (!PostMessageW(g_hWnd, msg, 0, (LPARAM)p)) free(p);
}
static void PushEvent(const std::wstring& s) {
    wchar_t t[32];
    SYSTEMTIME st; GetLocalTime(&st);
    swprintf_s(t, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    PostStr(WM_APP_LOG, t + s);
}

// ── logging from worker (loader-style, routed to UI) ───────────────────
static void Log(const char* fmt, ...) {
    char buf[1200];
    va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);
    wchar_t w[1200];
    MultiByteToWideChar(CP_ACP, 0, buf, -1, w, 1200);
    PushEvent(w);
}
static void Fail(const char* fmt, ...) {
    char buf[1200];
    va_list a; va_start(a, fmt);
    int n = snprintf(buf, sizeof(buf), "[FAIL] ");
    vsnprintf(buf + n, sizeof(buf) - n, fmt, a);
    va_end(a);
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " (err %lu)", GetLastError());
    Log("%s", buf);
}

// ── config (launcher.ini) ──────────────────────────────────────────────
static std::wstring IniGet(const wchar_t* key, const wchar_t* def) {
    wchar_t b[512];
    GetPrivateProfileStringW(L"main", key, def, b, 512, IniPath().c_str());
    return b;
}
static void IniSet(const wchar_t* key, const wchar_t* val) {
    WritePrivateProfileStringW(L"main", key, val, IniPath().c_str());
}
static void LoadConfig() {
    g_target = _wtoi(IniGet(L"target", L"0").c_str()) ? 1 : 0;
    wchar_t b[256];
    GetPrivateProfileStringW(L"auto", L"growtopia", L"", b, 256, IniPath().c_str());
    g_auto[0] = b;
    GetPrivateProfileStringW(L"auto", L"creative", L"", b, 256, IniPath().c_str());
    g_auto[1] = b;
}
static void SaveTarget() {
    wchar_t b[8]; swprintf_s(b, L"%d", g_target);
    IniSet(L"target", b);
}
static void SetAuto(int t, const std::wstring& name) {
    g_auto[t] = name;
    WritePrivateProfileStringW(L"auto", t == 0 ? L"growtopia" : L"creative",
                               name.empty() ? L"" : name.c_str(), IniPath().c_str());
    if (t == g_target) FillAutoCombo();
}

// ── process helpers (from loader.cpp) ──────────────────────────────────
static bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(0);
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    if (!ok || err != ERROR_SUCCESS) return false;
    Log("[+] SeDebugPrivilege enabled");
    return true;
}
static std::vector<DWORD> FindPids(const wchar_t* name) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, name) == 0) pids.push_back(pe.th32ProcessID); }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}
static BOOL CALLBACK EnumWinProc(HWND hw, LPARAM lParam) {
    DWORD wpid = 0; GetWindowThreadProcessId(hw, &wpid);
    if (wpid == (DWORD)lParam && IsWindowVisible(hw) && GetWindowTextLengthW(hw) > 0) return FALSE;
    return TRUE;
}
static bool ProcessHasWindow(DWORD pid) { return EnumWindows(EnumWinProc, (LPARAM)pid) == FALSE; }
static bool WaitForWindow(DWORD pid, int sec) {
    for (int i = 0; i < sec * 10; i++) {
        if (ProcessHasWindow(pid)) return true;
        Sleep(100);
    }
    return false;
}

// ── ACG / NtProtect / inject (from loader.cpp) ─────────────────────────
typedef BOOL(WINAPI* SetMitigationFn)(DWORD, PVOID, SIZE_T);
typedef BOOL(WINAPI* GetMitigationFn)(DWORD, PVOID, SIZE_T);

static bool DisableBlockDynamicCode(HANDLE hProc, DWORD pid) {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    auto SetPol = (SetMitigationFn)GetProcAddress(hK32, "SetProcessMitigationPolicy");
    auto GetPol = (GetMitigationFn)GetProcAddress(hK32, "GetProcessMitigationPolicy");
    if (!SetPol || !GetPol) return false;

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY cur{};
    if (GetProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy, &cur, sizeof(cur))) {
        if (!cur.ProhibitDynamicCode) { Log("[+] BlockDynamicCode already off"); return true; }
        Log("[*] BlockDynamicCode is ON — attempting remote disable...");
    }
    HMODULE remoteK32 = nullptr;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) { remoteK32 = (HMODULE)me.modBaseAddr; break; }
                while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
    }
    if (!remoteK32) return false;
    uintptr_t fnOff = (uintptr_t)SetPol - (uintptr_t)hK32;
    auto remoteSetPol = (LPVOID)((uintptr_t)remoteK32 + fnOff);

    BYTE sc[64]; int n = 0;
    sc[n++] = 0x48; sc[n++] = 0x83; sc[n++] = 0xEC; sc[n++] = 0x28;
    sc[n++] = 0xB9; sc[n++] = 0x02; sc[n++] = 0x00; sc[n++] = 0x00; sc[n++] = 0x00;
    sc[n++] = 0x48; sc[n++] = 0x8D; sc[n++] = 0x54; sc[n++] = 0x24; sc[n++] = 0x20;
    sc[n++] = 0x41; sc[n++] = 0xB8; sc[n++] = 0x04; sc[n++] = 0x00; sc[n++] = 0x00; sc[n++] = 0x00;
    sc[n++] = 0x31; sc[n++] = 0xC0;
    sc[n++] = 0x48; sc[n++] = 0x89; sc[n++] = 0x44; sc[n++] = 0x24; sc[n++] = 0x20;
    int callPos = n;
    sc[n++] = 0xE8; sc[n++] = 0x00; sc[n++] = 0x00; sc[n++] = 0x00; sc[n++] = 0x00;
    sc[n++] = 0x48; sc[n++] = 0x83; sc[n++] = 0xC4; sc[n++] = 0x28;
    sc[n++] = 0xC3;

    LPVOID remoteSc = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteSc) { Fail("VirtualAllocEx (mitigation stub)"); return false; }
    {
        intptr_t rel = (intptr_t)remoteSetPol - ((intptr_t)remoteSc + callPos + 5);
        memcpy(&sc[callPos + 1], &rel, 4);
    }
    if (!WriteProcessMemory(hProc, remoteSc, sc, n, nullptr)) {
        Fail("WriteProcessMemory (mitigation stub)");
        VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE);
        return false;
    }
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, remoteSc, n, PAGE_EXECUTE_READ, &oldProt)) {
        Fail("VirtualProtectEx (mitigation stub)");
        VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE);
        return false;
    }
    HANDLE hTh = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteSc, nullptr, 0, nullptr);
    if (!hTh) { Fail("CreateRemoteThread (mitigation stub)"); VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE); return false; }
    WaitForSingleObject(hTh, 5000);
    CloseHandle(hTh);
    VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE);

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY after{};
    if (GetProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy, &after, sizeof(after))) {
        if (!after.ProhibitDynamicCode) { Log("[-] BlockDynamicCode still ON — continuing anyway"); return false; }
        Log("[+] BlockDynamicCode disabled");
        return true;
    }
    return false;
}

static bool RvaToFileOffset(BYTE* file, DWORD rva, DWORD* outOff) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(file + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            *outOff = (rva - sec[i].VirtualAddress) + sec[i].PointerToRawData;
            return true;
        }
    }
    return false;
}

static bool RestoreNtProtectVirtualMemory(HANDLE hProc, DWORD pid) {
    HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
    auto pLocal = (BYTE*)GetProcAddress(hLocalNtdll, "NtProtectVirtualMemory");
    if (!pLocal) return false;
    DWORD rva = (DWORD)(pLocal - (BYTE*)hLocalNtdll);

    uintptr_t remoteNtdll = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W me{}; me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do if (_wcsicmp(me.szModule, L"ntdll.dll") == 0) { remoteNtdll = (uintptr_t)me.modBaseAddr; break; }
            while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    if (!remoteNtdll) return false;

    wchar_t ntdllPath[MAX_PATH]{};
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat_s(ntdllPath, L"\\ntdll.dll");
    HANDLE hf = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD fSize = GetFileSize(hf, nullptr);
    std::vector<BYTE> file(fSize);
    DWORD rd = 0; ReadFile(hf, file.data(), fSize, &rd, nullptr);
    CloseHandle(hf);

    DWORD fileOff = 0;
    if (!RvaToFileOffset(file.data(), rva, &fileOff)) return false;
    BYTE orig[16];
    memcpy(orig, file.data() + fileOff, sizeof(orig));
    BYTE current[16]{};
    ReadProcessMemory(hProc, (LPCVOID)(remoteNtdll + rva), current, sizeof(current), nullptr);
    if (memcmp(orig, current, sizeof(orig)) == 0) { Log("[+] NtProtectVirtualMemory already original"); return true; }

    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)(remoteNtdll + rva), sizeof(orig), PAGE_EXECUTE_READWRITE, &oldProt)) {
        Fail("VirtualProtectEx on remote ntdll"); return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)(remoteNtdll + rva), orig, sizeof(orig), &written)) {
        Fail("WriteProcessMemory on remote ntdll");
        VirtualProtectEx(hProc, (LPVOID)(remoteNtdll + rva), sizeof(orig), oldProt, &oldProt);
        return false;
    }
    DWORD tmp = 0;
    VirtualProtectEx(hProc, (LPVOID)(remoteNtdll + rva), sizeof(orig), oldProt, &tmp);
    Log("[+] NtProtectVirtualMemory restored to original bytes");
    return true;
}

static bool InjectDll(HANDLE hProc, const char* dllPath) {
    size_t len = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { Fail("VirtualAllocEx (dll path)"); return false; }
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, len, nullptr)) {
        Fail("WriteProcessMemory (dll path)"); VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE); return false;
    }
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hTh = CreateRemoteThread(hProc, nullptr, 0, loadLib, remoteMem, 0, nullptr);
    if (!hTh) { Fail("CreateRemoteThread (LoadLibraryA)"); VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE); return false; }
    WaitForSingleObject(hTh, 15000);
    DWORD code = 0; GetExitCodeThread(hTh, &code);
    CloseHandle(hTh);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    if (!code) { Log("[-] LoadLibraryA returned NULL — path wrong or dependency missing"); return false; }
    Log("[+] DLL injected (module base 0x%lX)", code);
    return true;
}

static HANDLE OpenTarget(DWORD pid) {
    return OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                       FALSE, pid);
}
static uintptr_t FindModuleBase(DWORD pid, std::wstring* nameOut) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    uintptr_t base = 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring m = me.szModule;
            std::wstring lo = m;
            std::transform(lo.begin(), lo.end(), lo.begin(), ::towlower);
            if (lo.rfind(L"epshax", 0) == 0 && lo.size() > 4 && lo.compare(lo.size() - 4, 4, L".dll") == 0) {
                base = (uintptr_t)me.modBaseAddr;
                if (nameOut) *nameOut = m;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

// ── remote PE export parsing + scriptBuf (port of inject_run.py) ───────
struct RemoteImg { std::vector<BYTE> img; DWORD soi = 0; };

static bool ReadRemote(HANDLE h, uintptr_t addr, void* buf, SIZE_T n) {
    SIZE_T got = 0;
    return ReadProcessMemory(h, (LPCVOID)addr, buf, n, &got) && got == n;
}
static bool ReadRemoteImage(HANDLE h, uintptr_t base, RemoteImg& out) {
    BYTE hdr[0x400];
    if (!ReadRemote(h, base, hdr, sizeof(hdr))) return false;
    IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)hdr;
    if (d->e_magic != IMAGE_DOS_SIGNATURE) return false;
    DWORD optOff = (DWORD)d->e_lfanew + 24;
    if (optOff + 60 > sizeof(hdr)) return false;
    DWORD soi = *(DWORD*)(hdr + optOff + 56);  // SizeOfImage
    if (soi < 0x1000 || soi > 0x4000000) return false;
    out.img.resize(soi);
    if (!ReadRemote(h, base, out.img.data(), soi)) return false;
    out.soi = soi;
    return true;
}
static bool ParseExports(const RemoteImg& im, std::map<std::string, DWORD>& out) {
    const BYTE* img = im.img.data();
    IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)img;
    DWORD e = (DWORD)d->e_lfanew;
    if ((size_t)e + 24 + 120 > im.soi) return false;
    WORD magic = *(WORD*)(img + e + 24);
    DWORD dd = e + 24 + (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112 : 96);
    if ((size_t)dd + 8 > im.soi) return false;
    DWORD erva = *(DWORD*)(img + dd);
    if (!erva || (size_t)erva + 40 > im.soi) return false;
    DWORD nn = *(DWORD*)(img + erva + 24);
    DWORD funcsR = *(DWORD*)(img + erva + 28);
    DWORD namesR = *(DWORD*)(img + erva + 32);
    DWORD ordsR  = *(DWORD*)(img + erva + 36);
    if ((size_t)namesR + (size_t)nn * 4 > im.soi ||
        (size_t)ordsR  + (size_t)nn * 2 > im.soi ||
        (size_t)funcsR + 4 > im.soi) return false;
    for (DWORD i = 0; i < nn; i++) {
        DWORD nr = *(DWORD*)(img + namesR + i * 4);
        if (nr >= im.soi) continue;
        const char* p = (const char*)img + nr;
        size_t maxl = im.soi - nr, l = 0;
        while (l < maxl && p[l]) l++;
        if (l >= maxl || !l) continue;
        WORD ordx = *(WORD*)(img + ordsR + i * 2);
        DWORD frva = *(DWORD*)(img + funcsR + (DWORD)ordx * 4);
        if (frva) out[std::string(p, l)] = frva;
    }
    return true;
}
static bool ResolveBufRva(const RemoteImg& im, DWORD frva, DWORD& bufRva) {
    DWORD r = frva;
    for (int hops = 0; hops < 8; hops++) {
        if ((size_t)r + 16 > im.soi) return false;
        const BYTE* c = im.img.data() + r;
        if (c[0] == 0xE9) { r = r + 5 + *(const int*)(c + 1); continue; }
        break;
    }
    const BYTE* c = im.img.data() + r;
    for (int i = 0; i + 7 <= 16; i++) {
        if (c[i] == 0x48 && c[i + 1] == 0x8D && c[i + 2] == 0x05) {
            int disp = *(const int*)(c + i + 3);
            DWORD br = r + (DWORD)i + 7 + (DWORD)disp;
            if ((size_t)br + 262144 <= im.soi) { bufRva = br; return true; }
            return false;
        }
    }
    return false;
}

// ── DLL discovery ──────────────────────────────────────────────────────
static std::wstring PickDll() {
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir = DirOf(self);
    std::wstring over = IniGet(L"dll", L"");
    if (!over.empty() && GetFileAttributesW(over.c_str()) != INVALID_FILE_ATTRIBUTES) return over;
    const wchar_t* names[] = { L"EpsHax7.dll", L"EpsHax6.dll", L"EpsHax5.dll", L"EpsHax4.dll",
                               L"EpsHax3.dll", L"EpsHax2.dll",
                               L"EpsHax.dll" };
    std::wstring best;
    FILETIME bestT{};
    for (int pass = 0; pass < 2; pass++) {
        std::wstring d = pass == 0 ? dir : DirOf(DirOf(dir)) + L"\\build\\Debug";
        for (auto n : names) {
            std::wstring p = d + L"\\" + n;
            WIN32_FILE_ATTRIBUTE_DATA f{};
            if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &f)) {
                if (best.empty() || CompareFileTime(&f.ftLastWriteTime, &bestT) > 0) {
                    best = p; bestT = f.ftLastWriteTime;
                }
            }
        }
        if (!best.empty()) break;
    }
    return best;
}
static std::string WideToAcp(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, 0);
    if (n > 1) WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    return s;
}

// ── launch game ────────────────────────────────────────────────────────
static bool LaunchGame(DWORD* outPid) {
    std::wstring exe = ExePath();
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("[-] exe not found: %ls", exe.c_str());
        return false;
    }
    std::wstring gameDir = DirOf(exe);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe + L"\"";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    if (!CreateProcessW(exe.c_str(), buf.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, gameDir.c_str(), &si, &pi)) {
        Fail("CreateProcessW");
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    *outPid = pi.dwProcessId;
    Log("[+] %ls started (pid %lu)", kTargets[g_target].label, pi.dwProcessId);
    return true;
}

// ── injection via EpsHaxLoader.exe (preferred path) ───────────────────
// Spawns "<selfdir>\EpsHaxLoader.exe -q -p <pid> <dll>", captures its
// output into the launcher log. Returns true only if the loader process
// exited 0 (loader prints its own diagnostics on failure).
static bool InjectViaLoader(const std::wstring& dllW, DWORD pid) {
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring loader = DirOf(self) + L"\\EpsHaxLoader.exe";
    if (GetFileAttributesW(loader.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("[*] EpsHaxLoader.exe not next to launcher");
        return false;
    }
    std::wstring cmd = L"\"" + loader + L"\" -q -p " + std::to_wstring(pid) +
                       L" \"" + dllW + L"\"";

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { Fail("CreatePipe (loader)"); return false; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    Log("[*] loader: %ls", cmd.c_str());
    if (!CreateProcessW(loader.c_str(), buf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        Fail("CreateProcessW (EpsHaxLoader)");
        return false;
    }
    CloseHandle(wr);

    // Drain pipe while waiting (no deadlock on 4K pipe buffer).
    std::string out;
    DWORD waited = 0;
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            char tmp[512]; DWORD n = 0;
            if (ReadFile(rd, tmp, avail < sizeof(tmp) ? avail : sizeof(tmp), &n, nullptr) && n)
                out.append(tmp, n);
        }
        if (WaitForSingleObject(pi.hProcess, 250) == WAIT_OBJECT_0) break;
        waited += 250;
        if (waited >= 150000) {
            Log("[-] loader timeout (150s) — terminating");
            TerminateProcess(pi.hProcess, 2);
            break;
        }
    }
    Sleep(50);
    for (;;) {  // final drain after exit
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) || !avail) break;
        char tmp[512]; DWORD n = 0;
        if (!ReadFile(rd, tmp, avail < sizeof(tmp) ? avail : sizeof(tmp), &n, nullptr) || !n) break;
        out.append(tmp, n);
    }
    CloseHandle(rd);
    DWORD code = 2;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    size_t s = 0;
    while (s < out.size()) {
        size_t e = out.find('\n', s);
        if (e == std::string::npos) e = out.size();
        std::string line = out.substr(s, e - s);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) Log("[loader] %s", line.c_str());
        s = e + 1;
    }
    if (code == 0) { Log("[+] loader injected pid %lu", pid); return true; }
    Log("[-] loader exit code %lu", code);
    return false;
}

// ── worker: play / inject / run ────────────────────────────────────────
static bool EnsureInjected(HANDLE* hOut, DWORD* pidOut) {
    const TargetInfo& t = kTargets[g_target];
    std::wstring scriptDir = ScriptDir();
    CreateDirectoryW(scriptDir.c_str(), nullptr);

    std::vector<DWORD> pids = FindPids(t.proc);
    DWORD pid = 0;
    if (pids.empty()) {
        PostStr(WM_APP_STATUS, std::wstring(L"Launching ") + t.label + L"...");
        if (!LaunchGame(&pid)) { PostStr(WM_APP_DONE, L"Launch failed"); return false; }
        PostStr(WM_APP_STATUS, L"Waiting for game window...");
        if (!WaitForWindow(pid, 90)) Log("[-] no window after 90s — injecting anyway");
        {
            HANDLE hw = OpenTarget(pid);
            if (hw) { WaitForInputIdle(hw, 10000); CloseHandle(hw); }
        }
        Sleep(2500);
    } else {
        pid = pids[0];
        if (pids.size() > 1) Log("[*] %zu instances of %ls — using pid %lu",
                                 pids.size(), t.proc, pid);
    }
    *pidOut = pid;

    HANDLE h = OpenTarget(pid);
    if (!h) { Fail("OpenProcess (pid %lu)", pid); PostStr(WM_APP_DONE, L"OpenProcess failed"); return false; }

    std::wstring modName;
    if (FindModuleBase(pid, &modName)) {
        Log("[+] %ls already loaded (%ls, pid %lu)", modName.c_str(), t.proc, pid);
        *hOut = h;
        return true;
    }

    PostStr(WM_APP_STATUS, L"Injecting EpsHax...");
    std::wstring dllW = PickDll();
    if (dllW.empty()) { Log("[-] no EpsHax DLL found next to launcher"); CloseHandle(h);
                        PostStr(WM_APP_DONE, L"EpsHax DLL not found"); return false; }
    Log("[+] DLL: %ls", dllW.c_str());
    if (!ProcessHasWindow(pid)) { Log("[*] waiting for window..."); WaitForWindow(pid, 90); }
    WaitForInputIdle(h, 10000);
    Sleep(1500);
    if (!InjectViaLoader(dllW, pid)) {
        Log("[*] loader unavailable/failed — falling back to built-in injection");
        DisableBlockDynamicCode(h, pid);
        RestoreNtProtectVirtualMemory(h, pid);
        if (!InjectDll(h, WideToAcp(dllW).c_str())) { CloseHandle(h);
            PostStr(WM_APP_DONE, L"Injection failed"); return false; }
    }
    Sleep(4000);  // first frame: ImGui init, executor ready
    if (!FindModuleBase(pid, &modName)) { CloseHandle(h);
        Log("[-] EpsHax not in module list after inject");
        PostStr(WM_APP_DONE, L"Injection failed (module missing)"); return false; }
    *hOut = h;
    return true;
}

static bool ExecuteScript(HANDLE h, DWORD pid, const std::wstring& scriptPath) {
    std::wstring modName;
    uintptr_t base = FindModuleBase(pid, &modName);
    if (!base) { Log("[-] EpsHax not loaded"); return false; }
    RemoteImg im;
    if (!ReadRemoteImage(h, base, im)) { Log("[-] remote image read failed"); return false; }
    std::map<std::string, DWORD> ex;
    if (!ParseExports(im, ex) || !ex.count("EpsHax_GetScriptBuf") || !ex.count("EpsHax_ExecuteScriptBuf")) {
        Log("[-] DLL exports missing (old build?)"); return false;
    }
    DWORD bufRva = 0;
    if (!ResolveBufRva(im, ex["EpsHax_GetScriptBuf"], bufRva)) {
        Log("[-] cannot resolve scriptBuf"); return false;
    }
    HANDLE hf = CreateFileW(scriptPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { Fail("open script"); return false; }
    DWORD sz = GetFileSize(hf, nullptr);
    if (sz >= 262144) { CloseHandle(hf); Log("[-] script too big (%lu)", sz); return false; }
    std::vector<char> data(sz + 1, 0);
    DWORD rd = 0; ReadFile(hf, data.data(), sz, &rd, nullptr);
    CloseHandle(hf);

    uintptr_t scriptAddr = base + bufRva;
    SIZE_T written = 0;
    if (!WriteProcessMemory(h, (LPVOID)scriptAddr, data.data(), sz + 1, &written)) {
        Fail("WriteProcessMemory (script)"); return false;
    }
    Log("[+] wrote %zu bytes to scriptBuf", (size_t)sz);
    uintptr_t execAddr = base + ex["EpsHax_ExecuteScriptBuf"];
    HANDLE hTh = CreateRemoteThread(h, nullptr, 0, (LPTHREAD_START_ROUTINE)execAddr, nullptr, 0, nullptr);
    if (!hTh) { Fail("CreateRemoteThread (execute)"); return false; }
    WaitForSingleObject(hTh, 15000);
    CloseHandle(hTh);
    return true;
}

static void Worker(int kind, std::wstring scriptPath) {
    EnableDebugPrivilege();
    std::wstring finalMsg;
    if (kind == 2) {  // run one script (game must be running)
        const TargetInfo& t = kTargets[g_target];
        std::vector<DWORD> pids = FindPids(t.proc);
        if (pids.empty()) {
            PostStr(WM_APP_STATUS, L"");
            PostStr(WM_APP_DONE, std::wstring(t.label) + L" is not running — press Play first");
        } else {
            DWORD pid = pids[0];
            std::wstring name = scriptPath.substr(scriptPath.find_last_of(L"\\/") + 1);
            HANDLE h = OpenTarget(pid);
            if (h && !FindModuleBase(pid, nullptr)) {
                CloseHandle(h); h = nullptr;
                if (!EnsureInjected(&h, &pid)) h = nullptr;
            }
            if (!h) {
                PostStr(WM_APP_STATUS, L"");
                PostStr(WM_APP_DONE, L"Inject failed — see Logs");
            } else {
                PostStr(WM_APP_STATUS, L"Running " + name + L"...");
                bool ok = ExecuteScript(h, pid, scriptPath);
                CloseHandle(h);
                PostStr(WM_APP_DONE, ok ? (L"Ran " + name) : (L"Failed: " + name));
            }
        }
    } else {  // 0 = play (launch if needed), 1 = inject only
        bool injectOnly = (kind == 1);
        const TargetInfo& t = kTargets[g_target];
        if (injectOnly && FindPids(t.proc).empty()) {
            PostStr(WM_APP_DONE, std::wstring(t.label) + L" is not running — press Play");
        } else {
            HANDLE h = nullptr; DWORD pid = 0;
            if (EnsureInjected(&h, &pid)) {
                if (kind == 0) {
                    // if the game is sitting at the login screen, click Play
                    std::wstring world;
                    if (ProbeWorld(h, pid, &world)) {
                        bool atLogin = world.empty() || world == L"?" || world == L"nil";
                        if (atLogin) {
                            PostStr(WM_APP_STATUS, L"Clicking Play in game...");
                            if (ClickGamePlay(pid)) {
                                PushEvent(L"[*] clicked Play in game — logging in");
                                Sleep(6000);
                            } else {
                                PushEvent(L"[-] game window not found for login click");
                            }
                        } else {
                            PushEvent(L"[+] world: " + world);
                        }
                    } else {
                        PushEvent(L"[-] world probe failed (log not readable yet)");
                    }
                }
                bool ran = false;
                std::wstring autoName = g_auto[g_target];
                if (kind == 0 && !autoName.empty()) {
                    std::wstring sp = ScriptDir() + L"\\" + autoName;
                    if (GetFileAttributesW(sp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        PostStr(WM_APP_STATUS, L"Auto-running " + autoName + L"...");
                        ran = ExecuteScript(h, pid, sp);
                    }
                }
                finalMsg = std::wstring(t.label) + L" ready (pid " + std::to_wstring(pid) + L")";
                if (ran) finalMsg += L" + " + g_auto[g_target];
                PostStr(WM_APP_DONE, finalMsg);
                CloseHandle(h);
            }
        }
    }
    PostMessageW(g_hWnd, WM_APP_DONE, 0, 0);  // signals busy=0 (with null string)
}

// ── UI helpers ─────────────────────────────────────────────────────────
static void SetBusy(BOOL b) {
    InterlockedExchange(&g_busy, b ? 1 : 0);
    EnableWindow(g_btnPlay, !b);
    EnableWindow(g_btnInject, !b);
    EnableWindow(g_btnRun, !b);
}
static void StartWork(int kind, const std::wstring& scriptPath = L"") {
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;
    g_foreOnStart = (g_hWnd && GetForegroundWindow() == g_hWnd);
    SetBusy(TRUE);
    if (g_worker.joinable()) g_worker.detach();
    g_worker = std::thread([=] { Worker(kind, scriptPath); });
}
static std::wstring GetSelScript() {
    int i = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (i < 0) return L"";
    wchar_t b[260];
    ListView_GetItemText(g_list, i, 0, b, 260);
    return b;
}
static void SelectByName(const std::wstring& name) {
    int cnt = ListView_GetItemCount(g_list);
    for (int i = 0; i < cnt; i++) {
        wchar_t b[260];
        ListView_GetItemText(g_list, i, 0, b, 260);
        if (_wcsicmp(b, name.c_str()) == 0) {
            ListView_SetItemState(g_list, i, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(g_list, i, FALSE);
            return;
        }
    }
}
static void SyncAutoCheck();
static void RefreshScripts() {
    ListView_DeleteAllItems(g_list);
    std::wstring dir = ScriptDir();
    CreateDirectoryW(dir.c_str(), nullptr);
    struct Ent { std::wstring name; DWORD size; FILETIME t; };
    std::vector<Ent> ents;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.lua").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                ents.push_back({ fd.cFileName,
                                 (fd.nFileSizeHigh << 16 | fd.nFileSizeLow), fd.ftLastWriteTime });
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::sort(ents.begin(), ents.end(), [](const Ent& a, const Ent& b) {
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });
    int row = 0;
    for (auto& e : ents) {
        LVITEMW it{};
        it.mask = LVIF_TEXT;
        it.iItem = row;
        it.pszText = const_cast<LPWSTR>(e.name.c_str());
        ListView_InsertItem(g_list, &it);
        wchar_t sz[32];
        if (e.size >= 1024) swprintf_s(sz, L"%lu.%lu KB", e.size / 1024, (e.size % 1024) / 103);
        else swprintf_s(sz, L"%lu B", e.size);
        ListView_SetItemText(g_list, row, 1, sz);
        SYSTEMTIME st;
        FileTimeToSystemTime(&e.t, &st);
        wchar_t dt[64];
        swprintf_s(dt, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay,
                   st.wHour, st.wMinute);
        ListView_SetItemText(g_list, row, 2, dt);
        row++;
    }
    if (!g_lastSel[g_target].empty()) SelectByName(g_lastSel[g_target]);
    SyncAutoCheck();
    FillAutoCombo();
}
static void SyncAutoCheck() {
    std::wstring s = GetSelScript();
    bool checked = !s.empty() && !g_auto[g_target].empty() &&
                   _wcsicmp(s.c_str(), g_auto[g_target].c_str()) == 0;
    SendMessageW(g_chkAuto, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    if (!s.empty()) g_lastSel[g_target] = s;
}
static void FillAutoCombo() {
    if (!g_autoCombo) return;
    std::wstring cur = g_auto[g_target];
    SendMessageW(g_autoCombo, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_autoCombo, CB_ADDSTRING, 0, (LPARAM)L"(none)");
    std::wstring dir = ScriptDir();
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.lua").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                names.push_back(fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::sort(names.begin(), names.end(), [](const std::wstring& a, const std::wstring& b) {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    });
    for (auto& n : names)
        SendMessageW(g_autoCombo, CB_ADDSTRING, 0, (LPARAM)n.c_str());
    int sel = 0;
    for (size_t i = 0; i < names.size(); i++) {
        if (_wcsicmp(names[i].c_str(), cur.c_str()) == 0) { sel = (int)i + 1; break; }
    }
    SendMessageW(g_autoCombo, CB_SETCURSEL, (WPARAM)sel, 0);
}
static void OnEditClicked();
static std::wstring Utf8OrAcpToWide(const char* p, int n) {
    std::wstring w;
    int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, n, nullptr, 0);
    if (need > 0) { w.resize(need); MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, n, &w[0], need); }
    else {
        need = MultiByteToWideChar(CP_ACP, 0, p, n, nullptr, 0);
        if (need > 0) { w.resize(need); MultiByteToWideChar(CP_ACP, 0, p, n, &w[0], need); }
    }
    while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n')) w.pop_back();
    return w;
}
static std::wstring FindGameLog() {
    const wchar_t* rel[] = {
        L"\\package-scanner-output\\Cmd Log\\log.txt",   // launched with cwd=game dir
        L"\\log.txt",                                     // game's own log
    };
    std::wstring gameDir = DirOf(ExePath());
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    // exe lives in <repo>\build\Debug → <repo>\package-scanner-output\...
    std::wstring devDir = DirOf(DirOf(DirOf(self))) + L"\\package-scanner-output\\Cmd Log\\log.txt";
    std::wstring best; FILETIME bestT{};
    auto consider = [&](const std::wstring& p) {
        if (p.empty()) return;
        WIN32_FILE_ATTRIBUTE_DATA f{};
        if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &f)) {
            if (best.empty() || CompareFileTime(&f.ftLastWriteTime, &bestT) > 0) {
                best = p; bestT = f.ftLastWriteTime;
            }
        }
    };
    consider(devDir);
    for (const wchar_t* r : rel) {
        if (r) consider(gameDir + r);
    }
    return best;
}
static void RebuildLogView() {
    std::wstring out;
    for (auto& e : g_events) { out += e; out += L"\r\n"; }
    out += L"--- game log tail ---\r\n";
    std::wstring lp = FindGameLog();
    if (lp.empty()) out += L"(no game log yet)\r\n";
    else {
        HANDLE h = CreateFileW(lp.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) out += L"(cannot open log)\r\n";
        else {
            LARGE_INTEGER sz{};
            GetFileSizeEx(h, &sz);
            DWORD toRead = sz.QuadPart > 65536 ? 65536 : (DWORD)sz.QuadPart;
            LARGE_INTEGER off{}; off.QuadPart = sz.QuadPart - toRead;
            SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
            std::vector<char> buf(toRead + 1, 0);
            DWORD rd = 0; ReadFile(h, buf.data(), toRead, &rd, nullptr);
            CloseHandle(h);
            std::wstring txt = Utf8OrAcpToWide(buf.data(), (int)rd);
            // keep last 150 lines
            size_t pos = 0, lines = 0, start = 0;
            for (size_t i = 0; i < txt.size(); i++) if (txt[i] == L'\n') { lines++; start = i + 1; }
            (void)pos;
            if (lines > 150) txt = txt.substr(start);
            out += txt;
            if (!txt.empty() && txt.back() != L'\n') out += L"\r\n";
        }
    }
    SetWindowTextW(g_editLog, out.c_str());
}

// ── world probe: is the game at the login screen or in a world? ────────
static bool ProbeWorld(HANDLE h, DWORD pid, std::wstring* out) {
    wchar_t tmp[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tmp)) return false;
    std::wstring probe = std::wstring(tmp) + L"epshax_wprobe.lua";
    FILE* f = nullptr;
    if (_wfopen_s(&f, probe.c_str(), L"wb") || !f) return false;
    const char* src =
        "local wn=\"?\"\n"
        "pcall(function() local w=GetWorld()\n"
        "  if w then wn=tostring(w.name or \"\") else wn=\"\" end end)\n"
        "pcall(function() log(\"[WPROBE] world=\"..wn) end)\n";
    fputs(src, f);
    fclose(f);
    if (!ExecuteScript(h, pid, probe)) return false;
    std::wstring lg = FindGameLog();
    if (lg.empty()) return false;
    HANDLE hf = CreateFileW(lg.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    GetFileSizeEx(hf, &sz);
    DWORD take = sz.QuadPart > 262144 ? 262144 : (DWORD)sz.QuadPart;
    LARGE_INTEGER off{}; off.QuadPart = sz.QuadPart - take;
    SetFilePointerEx(hf, off, nullptr, FILE_BEGIN);
    std::vector<char> buf(take + 1, 0);
    DWORD rd = 0; ReadFile(hf, buf.data(), take, &rd, nullptr);
    CloseHandle(hf);
    std::string all(buf.data(), rd);
    const std::string key = "[WPROBE] world=";
    size_t pos = all.rfind(key);
    if (pos == std::string::npos) return false;
    size_t e = all.find_first_of("\r\n", pos + key.size());
    std::string v = all.substr(pos + key.size(),
                               e == std::string::npos ? std::string::npos : e - (pos + key.size()));
    *out = Utf8OrAcpToWide(v.c_str(), (int)v.size());
    return true;
}

// ── click Play in the game window (login screen → world) ───────────────
struct FindWndCtx { DWORD pid; HWND found; };
static BOOL CALLBACK FindBigWndCb(HWND w, LPARAM lp) {
    auto* c = (FindWndCtx*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    if (pid != c->pid || !IsWindowVisible(w)) return TRUE;
    RECT r{};
    if (!GetWindowRect(w, &r)) return TRUE;
    if (r.right - r.left >= 400 && r.bottom - r.top >= 300) { c->found = w; return FALSE; }
    return TRUE;
}
static bool ClickGamePlay(DWORD pid) {
    FindWndCtx c{ pid, nullptr };
    EnumWindows(FindBigWndCb, (LPARAM)&c);
    if (!c.found) return false;
    HWND g = c.found;
    // bring the game to the foreground first — clicking a covered window
    // would hit whatever is on top (usually the launcher itself)
    if (IsIconic(g)) ShowWindow(g, SW_RESTORE);
    keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY, 0);
    SetForegroundWindow(g);
    keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
    SetForegroundWindow(g);
    Sleep(400);
    if (GetForegroundWindow() != g) {
        Log("[-] could not bring game window to foreground");
        return false;
    }
    RECT cr{};
    if (!GetClientRect(g, &cr)) return false;
    int cw = cr.right - cr.left, ch = cr.bottom - cr.top;
    if (cw < 400 || ch < 300) return false;
    // "Play Online" button center, in client coords of the 1024x689 menu
    POINT pt{ MulDiv(505, cw, 1024), MulDiv(388, ch, 689) };
    if (!ClientToScreen(g, &pt)) return false;
    SetCursorPos(pt.x - 40, pt.y);
    Sleep(150);
    SetCursorPos(pt.x, pt.y);
    Sleep(200);
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    Sleep(70);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    Log("[+] clicked Play in game at (%d,%d)", pt.x, pt.y);
    return true;
}

static void ShowPage(int idx) {
    if (idx < 0 || idx > 2) idx = 0;
    g_page = idx;
    if (g_tab) SendMessageW(g_tab, TCM_SETCURSEL, (WPARAM)idx, 0);
    for (int i = 0; i < 3; i++)
        ShowWindow(g_pages[i], i == idx ? SW_SHOW : SW_HIDE);
    if (idx == 2) RebuildLogView();
    if (idx == 1) RefreshScripts();
    // update part1 of status
    std::vector<DWORD> pids = FindPids(kTargets[g_target].proc);
    std::wstring s = std::wstring(L"target: ") + kTargets[g_target].label;
    s += pids.empty() ? L" | not running" : (L" | pid " + std::to_wstring(pids[0]));
    SendMessageW(g_status, SB_SETTEXTW, 1, (LPARAM)s.c_str());
}
static void UpdateTargetUI() {
    SendMessageW(g_radioGT, BM_SETCHECK, g_target == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_radioCG, BM_SETCHECK, g_target == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
    SetWindowTextW(g_gamePath, ExePath().c_str());
    SetWindowTextW(g_dllEdit, PickDll().c_str());
    FillAutoCombo();
    ShowPage(g_page);
}

static void SetStatusText(const wchar_t* s) {
    if (g_status) SendMessageW(g_status, SB_SETTEXTW, 0, (LPARAM)s);
    std::wstring t = L"EpsHax Launcher 1.0";
    if (s && *s) { t += L" — "; t += s; }
    if (g_hWnd) SetWindowTextW(g_hWnd, t.c_str());
}

// ── window proc ────────────────────────────────────────────────────────
static void OnRunClicked() {
    std::wstring s = GetSelScript();
    if (s.empty()) { MessageBoxW(g_hWnd, L"Select a script first.", L"EpsHax Launcher", MB_ICONINFORMATION); return; }
    g_lastSel[g_target] = s;
    StartWork(2, ScriptDir() + L"\\" + s);
}
static void OnNewClicked() {
    std::wstring dir = ScriptDir();
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path;
    for (int i = 0; i < 100; i++) {
        wchar_t nm[64];
        i == 0 ? swprintf_s(nm, L"NewScript.lua") : swprintf_s(nm, L"NewScript%d.lua", i);
        path = dir + L"\\" + nm;
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) break;
    }
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { MessageBoxW(g_hWnd, L"Cannot create file.", L"EpsHax Launcher", MB_ICONERROR); return; }
    const char* tpl = "-- EpsHax script\nlog(\"hello\")\n";
    DWORD wr = 0; WriteFile(h, tpl, (DWORD)strlen(tpl), &wr, nullptr);
    CloseHandle(h);
    PushEvent(L"created " + path.substr(path.find_last_of(L"\\/") + 1));
    RefreshScripts();
    SelectByName(path.substr(path.find_last_of(L"\\/") + 1));
    OnEditClicked();  // open editor
}
static void OnEditClicked() {
    std::wstring s = GetSelScript();
    if (s.empty()) return;
    std::wstring path = ScriptDir() + L"\\" + s;
    HINSTANCE r = ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, ScriptDir().c_str(), SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32)
        ShellExecuteW(nullptr, L"open", L"notepad.exe", (L"\"" + path + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
}
static void OnDeleteClicked() {
    std::wstring s = GetSelScript();
    if (s.empty()) return;
    std::wstring q = L"Delete " + s + L" ?";
    if (MessageBoxW(g_hWnd, q.c_str(), L"EpsHax Launcher", MB_YESNO | MB_ICONWARNING) != IDYES) return;
    DeleteFileW((ScriptDir() + L"\\" + s).c_str());
    if (_wcsicmp(g_auto[g_target].c_str(), s.c_str()) == 0) SetAuto(g_target, L"");
    PushEvent(L"deleted " + s);
    UpdateTargetUI();
}
static void OnOpenFolder() {
    CreateDirectoryW(ScriptDir().c_str(), nullptr);
    ShellExecuteW(nullptr, L"open", ScriptDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}
static void OnAutoCheck() {
    std::wstring s = GetSelScript();
    if (SendMessageW(g_chkAuto, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        if (s.empty()) {
            MessageBoxW(g_hWnd, L"Select a script to auto-run.", L"EpsHax Launcher", MB_ICONINFORMATION);
            SendMessageW(g_chkAuto, BM_SETCHECK, BST_UNCHECKED, 0);
            return;
        }
        SetAuto(g_target, s);
        PushEvent(L"auto-run set: " + s);
    } else {
        SetAuto(g_target, L"");
        PushEvent(L"auto-run cleared");
    }
    UpdateTargetUI();
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hWnd = hwnd;
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
        InitCommonControlsEx(&icc);
        g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        g_mono = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             0, 0, 0, 0, L"Consolas");

        g_tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                10, 10, 780, 490, hwnd, (HMENU)(INT_PTR)IDC_TAB,
                                GetModuleHandleW(nullptr), nullptr);
        TCITEMW ti{};
        ti.mask = TCIF_TEXT;
        ti.pszText = const_cast<LPWSTR>(L"Main");
        SendMessageW(g_tab, TCM_INSERTITEMW, 0, (LPARAM)&ti);
        ti.pszText = const_cast<LPWSTR>(L"Scripts");
        SendMessageW(g_tab, TCM_INSERTITEMW, 1, (LPARAM)&ti);
        ti.pszText = const_cast<LPWSTR>(L"Logs");
        SendMessageW(g_tab, TCM_INSERTITEMW, 2, (LPARAM)&ti);

        RECT rc; GetClientRect(g_tab, &rc);
        RECT inner = rc;
        SendMessageW(g_tab, TCM_ADJUSTRECT, FALSE, (LPARAM)&inner);

        // ---- page 0: Main ----
        g_pages[0] = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                     inner.left, inner.top, inner.right - inner.left,
                                     inner.bottom - inner.top, g_tab, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
        HWND p0 = g_pages[0];
        g_p0 = p0;
        CreateWindowExW(0, L"BUTTON", L"Target game", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                        15, 10, 350, 105, p0, nullptr, GetModuleHandleW(nullptr), nullptr);
        g_radioGT = CreateWindowExW(0, L"BUTTON", L"Growtopia", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                        32, 35, 200, 20, p0, (HMENU)(INT_PTR)IDC_RADIO_GT, GetModuleHandleW(nullptr), nullptr);
        g_radioCG = CreateWindowExW(0, L"BUTTON", L"Creative Growtopia", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                        32, 60, 250, 20, p0, (HMENU)(INT_PTR)IDC_RADIO_CG, GetModuleHandleW(nullptr), nullptr);
        g_gamePath = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_PATHELLIPSIS,
                        32, 84, 320, 18, p0, (HMENU)(INT_PTR)IDC_GAMEPATH, GetModuleHandleW(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"EpsHax DLL (auto-picked, newest build)", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                        15, 122, 745, 62, p0, nullptr, GetModuleHandleW(nullptr), nullptr);
        g_dllEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
                                       32, 146, 710, 20, p0, (HMENU)(INT_PTR)IDC_DLLPATH,
                                       GetModuleHandleW(nullptr), nullptr);

        g_btnPlay = CreateWindowExW(0, L"BUTTON", L"Play", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                    15, 198, 130, 40, p0, (HMENU)(INT_PTR)IDC_BTN_PLAY,
                                    GetModuleHandleW(nullptr), nullptr);
        g_btnInject = CreateWindowExW(0, L"BUTTON", L"Inject only", WS_CHILD | WS_VISIBLE,
                                      155, 198, 130, 40, p0, (HMENU)(INT_PTR)IDC_BTN_INJECT,
                                      GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"BUTTON", L"Open scripts folder", WS_CHILD | WS_VISIBLE,
                        295, 198, 160, 40, p0, (HMENU)(INT_PTR)IDC_BTN_FOLDER,
                        GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"STATIC", L"Script to run on Play:",
                        WS_CHILD | WS_VISIBLE,
                        15, 255, 155, 18, p0, nullptr,
                        GetModuleHandleW(nullptr), nullptr);
        g_autoCombo = CreateWindowExW(0, WC_COMBOBOXW, L"",
                        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                        175, 250, 430, 250, p0, (HMENU)(INT_PTR)IDC_STATIC_AUTO,
                        GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"STATIC",
                        L"Play: starts the game if needed, injects EpsHax, clicks Play in game to log in,\r\n"
                        L"then runs the script selected above.  Scripts tab: manage .lua files.",
                        WS_CHILD | WS_VISIBLE,
                        15, 282, 745, 44, p0, nullptr, GetModuleHandleW(nullptr), nullptr);

        // ---- page 1: Scripts ----
        g_pages[1] = CreateWindowExW(0, L"STATIC", L"", WS_CHILD,
                                     inner.left, inner.top, inner.right - inner.left,
                                     inner.bottom - inner.top, g_tab, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
        HWND p1 = g_pages[1];
        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 10, 10, inner.right - inner.left - 20, inner.bottom - inner.top - 62,
                                 p1, (HMENU)(INT_PTR)IDC_LIST, GetModuleHandleW(nullptr), nullptr);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(L"Name"); col.cx = 320;
        ListView_InsertColumn(g_list, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"Size"); col.cx = 90;
        ListView_InsertColumn(g_list, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"Modified"); col.cx = 150;
        ListView_InsertColumn(g_list, 2, &col);

        int by = inner.bottom - inner.top - 46;
        int bx = 10;
        auto mkBtn = [&](const wchar_t* txt, int w, int id) {
            HWND b = CreateWindowExW(0, L"BUTTON", txt, WS_CHILD | WS_VISIBLE,
                                     bx, by, w, 32, p1, (HMENU)(INT_PTR)id,
                                     GetModuleHandleW(nullptr), nullptr);
            bx += w + 8;
            return b;
        };
        g_btnRun = mkBtn(L"Run", 80, IDC_BTN_RUN);
        mkBtn(L"Refresh", 80, IDC_BTN_REFRESH);
        mkBtn(L"New", 70, IDC_BTN_NEW);
        mkBtn(L"Edit", 70, IDC_BTN_EDIT);
        mkBtn(L"Delete", 80, IDC_BTN_DELETE);
        mkBtn(L"Open folder", 100, IDC_BTN_FOLDER2);
        g_chkAuto = CreateWindowExW(0, L"BUTTON", L"Auto-run on Play",
                                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                    bx + 8, by + 7, 170, 20, p1, (HMENU)(INT_PTR)IDC_CHK_AUTO,
                                    GetModuleHandleW(nullptr), nullptr);

        // ---- page 2: Logs ----
        g_pages[2] = CreateWindowExW(0, L"STATIC", L"", WS_CHILD,
                                     inner.left, inner.top, inner.right - inner.left,
                                     inner.bottom - inner.top, g_tab, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
        HWND p2 = g_pages[2];
        g_editLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_READONLY,
                                    10, 10, inner.right - inner.left - 20,
                                    inner.bottom - inner.top - 56, p2,
                                    (HMENU)(INT_PTR)IDC_EDIT_LOG,
                                    GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g_editLog, WM_SETFONT, (WPARAM)g_mono, TRUE);
        CreateWindowExW(0, L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE,
                        10, inner.bottom - inner.top - 42, 90, 28, p2,
                        (HMENU)(INT_PTR)IDC_BTN_LOGREF, GetModuleHandleW(nullptr), nullptr);
        CreateWindowExW(0, L"STATIC",
                        L"launcher events (top) + tail of the newest game log — auto-refresh 2s",
                        WS_CHILD | WS_VISIBLE, 110, inner.bottom - inner.top - 36, 560, 18,
                        p2, nullptr, GetModuleHandleW(nullptr), nullptr);

        // status bar
        g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
                                   WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                   0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_STATUSBAR,
                                   GetModuleHandleW(nullptr), nullptr);
        int parts[2] = { 560, -1 };
        SendMessageW(g_status, SB_SETPARTS, 2, (LPARAM)parts);
        SetStatusText(L"Ready");
        SendMessageW(g_status, SB_SETTEXTW, 1, (LPARAM)L"target: Growtopia");

        // fonts to children
        auto fontAll = [](HWND parent) {
            for (HWND c = GetWindow(parent, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
                SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        };
        fontAll(p0); fontAll(p1); fontAll(p2);
        SendMessageW(g_dllEdit, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_editLog, WM_SETFONT, (WPARAM)g_mono, TRUE);

        LoadConfig();
        UpdateTargetUI();
        RefreshScripts();
        PushEvent(L"launcher started (target: " + std::wstring(kTargets[g_target].label) + L")");
        SetTimer(hwnd, 1, 2000, nullptr);
        return 0;
    }

    case WM_TIMER:
        if (wParam == 1 && !g_busy && g_page == 2) RebuildLogView();
        return 0;

    case WM_NOTIFY: {
        LPNMHDR nm = (LPNMHDR)lParam;
        if (nm->code == TCN_SELCHANGE && nm->idFrom == IDC_TAB)
            ShowPage((int)SendMessageW(g_tab, TCM_GETCURSEL, 0, 0));
        if (nm->idFrom == IDC_LIST) {
            if (nm->code == NM_DBLCLK) OnRunClicked();
            else if (nm->code == LVN_ITEMCHANGED) {
                NMLISTVIEW* lv = (NMLISTVIEW*)lParam;
                if ((lv->uNewState ^ lv->uOldState) & LVIS_SELECTED) SyncAutoCheck();
            }
        }
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);
        if (id == IDC_RADIO_GT && code == BN_CLICKED) { g_target = 0; SaveTarget(); UpdateTargetUI(); }
        else if (id == IDC_RADIO_CG && code == BN_CLICKED) { g_target = 1; SaveTarget(); UpdateTargetUI(); }
        else if (id == IDC_BTN_PLAY) StartWork(0);
        else if (id == IDC_BTN_INJECT) StartWork(1);
        else if (id == IDC_BTN_RUN) OnRunClicked();
        else if (id == IDC_BTN_REFRESH) RefreshScripts();
        else if (id == IDC_BTN_NEW) OnNewClicked();
        else if (id == IDC_BTN_EDIT) OnEditClicked();
        else if (id == IDC_BTN_DELETE) OnDeleteClicked();
        else if (id == IDC_BTN_FOLDER || id == IDC_BTN_FOLDER2) OnOpenFolder();
        else if (id == IDC_CHK_AUTO && code == BN_CLICKED) OnAutoCheck();
        else if (id == IDC_STATIC_AUTO && code == CBN_SELCHANGE) {
            int i = (int)SendMessageW(g_autoCombo, CB_GETCURSEL, 0, 0);
            std::wstring sel;
            if (i > 0) {
                wchar_t b[260] = {};
                if (SendMessageW(g_autoCombo, CB_GETLBTEXT, (WPARAM)i, (LPARAM)b) != CB_ERR)
                    sel = b;
            }
            SetAuto(g_target, sel);
            SyncAutoCheck();
            PushEvent(sel.empty() ? L"auto-run cleared" : (L"auto-run set: " + sel));
        }
        else if (id == IDC_BTN_LOGREF) RebuildLogView();
        return 0;
    }

    case WM_APP_LOG: {
        wchar_t* s = (wchar_t*)lParam;
        if (s) {
            g_events.insert(g_events.begin(), s);
            if (g_events.size() > 60) g_events.resize(60);
            free(s);
            if (g_page == 2 && !g_busy) RebuildLogView();
        }
        return 0;
    }
    case WM_APP_STATUS: {
        wchar_t* s = (wchar_t*)lParam;
        SetStatusText(s ? s : L"");
        free(s);
        return 0;
    }
    case WM_APP_DONE: {
        wchar_t* s = (wchar_t*)lParam;
        if (s) {
            SetStatusText(s);
            PushEvent(s);
            free(s);
        }
        SetBusy(FALSE);
        if (g_foreOnStart && g_hWnd) {
            g_foreOnStart = false;
            if (IsIconic(g_hWnd)) ShowWindow(g_hWnd, SW_RESTORE);
            SwitchToThisWindow(g_hWnd, TRUE);
            SetForegroundWindow(g_hWnd);
        }
        return 0;
    }

    case WM_COPYDATA: {
        COPYDATASTRUCT* cds = (COPYDATASTRUCT*)lParam;
        if (!cds || !cds->lpData || cds->cbData < 2) return FALSE;
        size_t nchars = cds->cbData / sizeof(wchar_t);
        std::wstring c((const wchar_t*)cds->lpData, nchars);
        while (!c.empty() && c.back() == L'\0') c.pop_back();
        if (c == L"page 0") ShowPage(0);
        else if (c == L"page 1") ShowPage(1);
        else if (c == L"page 2") ShowPage(2);
        else if (c == L"play") StartWork(0);
        else if (c == L"inject") StartWork(1);
        else if (c.rfind(L"run ", 0) == 0) {
            std::wstring name = c.substr(4);
            SelectByName(name);
            StartWork(2, ScriptDir() + L"\\" + name);
        } else if (c.rfind(L"auto ", 0) == 0) {
            std::wstring arg = c.substr(5);
            SetAuto(g_target, arg == L"clear" ? L"" : arg);
            UpdateTargetUI();
            PushEvent(arg == L"clear" ? L"auto-run cleared" : (L"auto-run set: " + arg));
        } else {
            return FALSE;
        }
        return TRUE;
    }

    case WM_CLOSE:
        if (g_busy) {
            MessageBoxW(hwnd, L"An operation is running — please wait.", L"EpsHax Launcher",
                        MB_ICONINFORMATION);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"EpsHaxLauncherWnd";
    RegisterClassW(&wc);

    g_hWnd = CreateWindowExW(0, L"EpsHaxLauncherWnd",
                             L"EpsHax Launcher 1.0",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 800, 566,
                             nullptr, nullptr, hInst, nullptr);
    if (!g_hWnd) return 1;

    // center over work area
    RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    RECT wr; GetWindowRect(g_hWnd, &wr);
    int w = wr.right - wr.left, h = wr.bottom - wr.top;
    SetWindowPos(g_hWnd, nullptr, wa.left + ((wa.right - wa.left) - w) / 2,
                 wa.top + ((wa.bottom - wa.top) - h) / 2, 0, 0,
                 SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_worker.joinable()) g_worker.detach();
    return (int)m.wParam;
}
