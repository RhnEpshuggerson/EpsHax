#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#include "discord_rpc.h"

namespace discordrpc {
namespace {

constexpr const char* kClientId = "1552954491148566548";
constexpr const char* kImage =
    "https://media1.tenor.com/m/dDGDWm21Jv8AAAAd/chud-matrix.gif";
constexpr const char* kDetails = "EpsHax Executor";
constexpr const char* kState   = "Playing Growtopia";

enum : uint32_t {
    OP_HANDSHAKE = 0,
    OP_FRAME     = 1,
    OP_CLOSE     = 2,
    OP_PING      = 3,
    OP_PONG      = 4,
};

LogFn g_log = nullptr;

void Log(const char* m) {
    if (g_log) g_log(m);
}

bool WriteAll(HANDLE h, const void* data, DWORD len) {
    const uint8_t* p = (const uint8_t*)data;
    while (len) {
        DWORD written = 0;
        if (!WriteFile(h, p, len, &written, nullptr) || written == 0) return false;
        p += written;
        len -= written;
    }
    return true;
}

bool SendFrame(HANDLE h, uint32_t op, const std::string& payload) {
    const uint32_t n = (uint32_t)payload.size();
    uint8_t hdr[8] = {
        (uint8_t)op, (uint8_t)(op >> 8), (uint8_t)(op >> 16), (uint8_t)(op >> 24),
        (uint8_t)n,  (uint8_t)(n >> 8),  (uint8_t)(n >> 16),  (uint8_t)(n >> 24),
    };
    if (!WriteAll(h, hdr, sizeof(hdr))) return false;
    if (n && !WriteAll(h, payload.data(), n)) return false;
    return true;
}

bool ReadAll(HANDLE h, void* data, DWORD len) {
    uint8_t* p = (uint8_t*)data;
    while (len) {
        DWORD got = 0;
        if (!ReadFile(h, p, len, &got, nullptr) || got == 0) return false;
        p += got;
        len -= got;
    }
    return true;
}

bool ReadFrame(HANDLE h, uint32_t& op, std::string& payload) {
    uint8_t hdr[8];
    if (!ReadAll(h, hdr, sizeof(hdr))) return false;
    op = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
         ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    uint32_t n = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                 ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
    if (n > (1u << 20)) return false;
    payload.assign(n, '\0');
    if (n && !ReadAll(h, &payload[0], n)) return false;
    return true;
}

HANDLE ConnectPipe() {
    for (int i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "\\\\.\\pipe\\discord-ipc-%d", i);
        HANDLE h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) return h;
    }
    return INVALID_HANDLE_VALUE;
}

std::string BuildSetActivity(bool withAssets, long long startTs) {
    const long long now = (long long)time(nullptr);
    char act[640];
    if (withAssets) {
        snprintf(act, sizeof(act),
                 "{\"type\":0,"
                 "\"details\":\"%s\","
                 "\"state\":\"%s\","
                 "\"timestamps\":{\"start\":%lld},"
                 "\"assets\":{\"large_image\":\"%s\",\"large_text\":\"EpsHax\"}}",
                 kDetails, kState, startTs, kImage);
    } else {
        // Fallback: Discord can reject activities whose external image URL is
        // no longer allowed — retry without assets so presence still shows.
        snprintf(act, sizeof(act),
                 "{\"type\":0,"
                 "\"details\":\"%s\","
                 "\"state\":\"%s\","
                 "\"timestamps\":{\"start\":%lld}}",
                 kDetails, kState, startTs);
    }
    (void)now;
    char msg[768];
    snprintf(msg, sizeof(msg),
             "{\"cmd\":\"SET_ACTIVITY\",\"args\":{\"pid\":%lu,\"activity\":%s},"
             "\"nonce\":\"%llu-%llu\"}",
             (unsigned long)GetCurrentProcessId(), act,
             (unsigned long long)GetTickCount64(),
             (unsigned long long)GetCurrentProcessId());
    return msg;
}

constexpr DWORD kRefreshMs = 10 * 60 * 1000;  // re-send presence every 10 min
constexpr DWORD kPollMs = 250;

DWORD WINAPI ThreadMain(LPVOID) {
    bool waitLogged = false;
    for (;;) {
        HANDLE h = ConnectPipe();
        if (h == INVALID_HANDLE_VALUE) {
            if (!waitLogged) {
                Log("Discord not running - presence starts when it opens");
                waitLogged = true;
            }
            Sleep(5000);
            continue;
        }
        waitLogged = false;

        const std::string hs =
            std::string("{\"v\":1,\"client_id\":\"") + kClientId + "\"}";
        if (!SendFrame(h, OP_HANDSHAKE, hs)) {
            CloseHandle(h);
            Sleep(3000);
            continue;
        }

        bool ready = false;
        for (int i = 0; i < 8 && !ready; i++) {
            uint32_t op;
            std::string p;
            if (!ReadFrame(h, op, p)) break;
            if (op == OP_PING) {
                if (!SendFrame(h, OP_PONG, p)) break;
                continue;
            }
            if (op == OP_FRAME) {
                if (p.find("\"READY\"") != std::string::npos) ready = true;
                else if (p.find("ERROR") != std::string::npos) break;
            }
        }
        if (!ready) {
            Log("handshake failed - retrying");
            CloseHandle(h);
            Sleep(5000);
            continue;
        }

        // One start timestamp per process: refreshes keep the session timer.
        static const long long startTs = (long long)time(nullptr);
        static bool s_assetsFallback = false;
        bool withAssets = !s_assetsFallback;
        if (!SendFrame(h, OP_FRAME, BuildSetActivity(withAssets, startTs))) {
            CloseHandle(h);
            Sleep(3000);
            continue;
        }
        DWORD lastSend = GetTickCount();
        Log(s_assetsFallback
                ? "connected - EpsHax presence active (no image)"
                : "connected - EpsHax presence active");

        bool awaitingReply = true;
        bool fallbackTried = s_assetsFallback;
        for (;;) {
            // Poll instead of blocking so we can refresh presence periodically.
            DWORD avail = 0;
            if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) break; // pipe gone
            if (avail >= 8) {
                uint32_t op;
                std::string p;
                if (!ReadFrame(h, op, p)) break;
                if (op == OP_PING) {
                    if (!SendFrame(h, OP_PONG, p)) break;
                } else if (op == OP_CLOSE) {
                    break;
                } else if (op == OP_FRAME && awaitingReply &&
                           p.find("SET_ACTIVITY") != std::string::npos) {
                    awaitingReply = false;
                    if (p.find("ERROR") != std::string::npos) {
                        Log(("presence rejected: " + p).c_str());
                        if (!fallbackTried) {
                            // Retry once without assets (external URL may be rejected).
                            fallbackTried = true;
                            s_assetsFallback = true;
                            withAssets = false;
                            if (SendFrame(h, OP_FRAME,
                                          BuildSetActivity(false, startTs))) {
                                lastSend = GetTickCount();
                                awaitingReply = true;
                                Log("retrying presence without image...");
                            }
                        }
                    } else {
                        Log("presence confirmed by Discord");
                    }
                }
            }
            DWORD now = GetTickCount();
            if (now - lastSend >= kRefreshMs) {
                withAssets = !s_assetsFallback;
                if (SendFrame(h, OP_FRAME, BuildSetActivity(withAssets, startTs))) {
                    lastSend = now;
                    awaitingReply = true;
                    Log("presence refreshed");
                } else break;
            }
            Sleep(kPollMs);
        }

        Log("Discord connection lost - reconnecting");
        CloseHandle(h);
        Sleep(3000);
    }
    return 0;
}

} // namespace

void Start(LogFn log) {
    g_log = log;
    HANDLE t = CreateThread(nullptr, 0, ThreadMain, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

} // namespace discordrpc
