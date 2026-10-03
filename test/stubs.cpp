// Link-time stand-ins for hook.cpp / dllmain.cpp / scanner.cpp so ApiTest
// can exercise lua_api.cpp + lua_bothax.cpp + itemdb.cpp without the game.
// Captured sends are exposed for assertions in api_test.cpp.
#include "hook.h"
#include "lua_api.h"
#include <windows.h>
#include <cstdio>
#include <utility>
#include <vector>

float g_currentTime = 0;
bool g_debugMode = false;
bool g_Initialized = false;
bool g_MenuOpen = false;
bool g_SocketHooksInstalled = false;
HWND g_GameHWND = nullptr;
LuaExecutor* g_executor = nullptr;
std::atomic<bool> g_OnTankPacket{false};
std::unordered_set<std::string> g_luaCommands;
std::atomic<uintptr_t> g_TileBegin{0};
std::atomic<int> g_TileW{0};
std::atomic<int> g_TileH{0};

// captured outbound traffic (type, payload)
std::vector<std::pair<int, std::string>> g_SentText;
std::vector<std::pair<int, std::vector<uint8_t>>> g_SentRaw;

namespace scanner {
// host-test values: no game ctx / no image base (lua_api falls back safely)
uintptr_t fn_GetCtx = 0;
uintptr_t g_GameBase = 0;
size_t g_GameImageSize = 0;
bool IsCreativeBuild() { return false; } // host tests exercise the GT layout
void CallSendPacket(int type, const char* text) {
    g_SentText.push_back({type, text ? text : ""});
    printf("[SENT type=%d] %.120s\n", type, text ? text : "");
}
void CallSendPacketBin(int type, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    g_SentRaw.push_back({type, std::vector<uint8_t>(p, p + len)});
    printf("[SENTBIN type=%d len=%zu]\n", type, len);
}
} // namespace scanner

void debugLog(const std::string& msg) {
    {
        std::lock_guard<std::mutex> lk(g_debugMutex);
        g_debugLogs.push_back({msg, g_currentTime});
        if (g_debugLogs.size() > 500) g_debugLogs.erase(g_debugLogs.begin());
    }
    printf("[DBG] %s\n", msg.c_str());
}

// fake tile arena used by the SetTileFlags test — stub SyncGameCaches must
// NOT clobber g_TileBegin (the real one would read game memory)
void SyncGameCaches(bool) {}

GameState& GameState::instance() {
    static GameState gs;
    return gs;
}

void GameState::pushEvent(const PacketEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx);
    if (events.size() < 1000) events.push(ev);
}

bool GameState::popEvent(PacketEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx);
    if (events.empty()) return false;
    ev = events.front();
    events.pop();
    return true;
}
