#pragma once
#include <lua.hpp>
#include <string>
#include <vector>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>

extern bool g_debugMode;
extern float g_currentTime;
void debugLog(const std::string& msg);

struct LogEntry {
    std::string message;
    float time;
};

// deque: push_back/pop_front are O(1) and never move existing LogEntry
// strings — the old vector erase(begin()) shifted 500/1000 string objects
// per line under the debug CRT's shared container locks, which deadlocked
// the render thread against concurrently-logging net threads.
extern std::mutex g_consoleMutex;
extern std::deque<LogEntry> g_consoleLogs;
void consoleLog(const std::string& msg);

extern std::mutex g_debugMutex;
extern std::deque<LogEntry> g_debugLogs;

// Serializes ALL Lua access: render-thread tick, execute()/stop() (run on a
// detached thread from the menu), and the sync bothax hook dispatch from
// the network threads. recursive — a lua handler may SendPacket, which
// re-enters parseOutgoing -> dispatch on the same thread.
extern std::recursive_mutex g_LuaMtx;

// bothax RunDelayed(ms, fn, ...) pending fire list (ticked in LuaExecutor::tick)
struct DelayedInfo {
    float fireAt = 0;
    int ref = 0;
    std::vector<int> argRefs;
};

struct CallbackInfo {
    std::string name;
    std::string type;
    int ref;
};

struct TimerInfo {
    std::string name;
    float interval;   // seconds (matches GrowPai timer.Create semantics)
    int repeat;
    int ref;
    float lastTick;
};

struct LuaThreadInfo {
    lua_State* co;
    float resumeTime;
    int ref;
};

class LuaExecutor {
public:
    LuaExecutor();
    ~LuaExecutor();

    bool execute(const std::string& script);
    void stop();
    bool isRunning() const { return running; }
    void tick(float dt);

    void registerAPI();

    lua_State* getLuaState() { return L; }
    void setTickInterval(float s) { tickInterval = s; }

    std::vector<CallbackInfo> callbacks;
    std::vector<TimerInfo> timers;
    std::vector<LuaThreadInfo> threads;
    std::vector<DelayedInfo> delayed;
    // RegisterCommand("name", fn) — slash-commands typed in chat
    std::map<std::string, int> commands;

private:
    lua_State* L = nullptr;
    std::atomic<bool> running{false};
    float startTime = 0;
    float lastTickTime = 0;
    float tickInterval = 1.0f;

    static int lua_SendPacket(lua_State* L);
    static int lua_SendPacketRaw(lua_State* L);
    static int lua_SendVarlist(lua_State* L);
    static int lua_log(lua_State* L);
    static int lua_GetLocal(lua_State* L);
    static int lua_GetInventory(lua_State* L);
    static int lua_GetPlayers(lua_State* L);
    static int lua_GetObjects(lua_State* L);
    static int lua_GetTile(lua_State* L);
    static int lua_GetTiles(lua_State* L);
    static int lua_FindPath(lua_State* L);
    static int lua_PathFind(lua_State* L);
    static int lua_CheckPath(lua_State* L);
    static int lua_IsSolid(lua_State* L);
    static int lua_RunThread(lua_State* L);
    static int lua_Sleep(lua_State* L);
    static int lua_GetPing(lua_State* L);
    static int lua_GetItemCount(lua_State* L);
    static int lua_GetItemInfo(lua_State* L);
    static int lua_MessageBox(lua_State* L);
    static int lua_RemoveCallbacks(lua_State* L);
    static int lua_RemoveCallback(lua_State* L);
    static int lua_EditToggle(lua_State* L);
    static int lua_SendWebhook(lua_State* L);
    static int lua_timer_Create(lua_State* L);
    static int lua_timer_Destroy(lua_State* L);
    static int lua_timer_Update(lua_State* L);
    static int lua_GetGhost(lua_State* L);
    static int lua_GetAccesslist(lua_State* L);
    static int lua_GetLocalObject(lua_State* L);
    static int lua_GetDroppedItems(lua_State* L);
    static int lua_AddCallback(lua_State* L);
    static int lua_RegisterCommand(lua_State* L);
    // GrowPai compat
    static int lua_GetWorld(lua_State* L);
    static int lua_AddHook(lua_State* L);
    static int lua_MakeRequest(lua_State* L);
    // thread helper shared by RunThread/LoadEncrypt/LoadEncryptedFile:
    // pushes fn+args onto a new coroutine, resumes it, tracks yields
    static void startThread(lua_State* L, int fnIndex, int nargs);

    // ── bothax API (impl in lua_bothax.cpp) ──────────────────────────
    static int lua_ChangeValue(lua_State* L);
    static int lua_Encrypt(lua_State* L);
    static int lua_EncryptFile(lua_State* L);
    static int lua_LoadEncrypt(lua_State* L);
    static int lua_LoadEncryptedFile(lua_State* L);
    static int lua_GetCamera(lua_State* L);
    static int lua_GetClient(lua_State* L);
    static int lua_GetItemByIDSafe(lua_State* L);
    static int lua_GetItemByName(lua_State* L);
    static int lua_GetItemInfoList(lua_State* L);
    static int lua_GetItemsByPartialName(lua_State* L);
    static int lua_GetNPC(lua_State* L);
    static int lua_GetNPCList(lua_State* L);
    static int lua_GetObjectList(lua_State* L);
    static int lua_GetPlayer(lua_State* L);
    static int lua_GetPlayerInfo(lua_State* L);
    static int lua_GetPlayerItems(lua_State* L);
    static int lua_GetPlayerList(lua_State* L);
    static int lua_Hash32(lua_State* L);
    static int lua_Hash64(lua_State* L);
    static int lua_RemoveHook(lua_State* L);
    static int lua_RemoveHooks(lua_State* L);
    static int lua_RequestJoinWorld(lua_State* L);
    static int lua_RunDelayed(lua_State* L);
    static int lua_SetItemSelected(lua_State* L);
    static int lua_SetTileFlags(lua_State* L);
    static int lua_SendVariantListBx(lua_State* L);
    static int lua_SendPacketRawBx(lua_State* L);
    static int lua_MakeRequestBx(lua_State* L);

    // shared table pushers (used by lua_api.cpp reshapes + lua_bothax.cpp)
    static void pushTileFlags(lua_State* L, int rawFlags);
    static void pushTileCommon(lua_State* L, const struct TileData& t, int x, int y, bool inBounds);
    static void pushItemInfo(lua_State* L, const struct ItemInfo& it);
    static void pushAvatar(lua_State* L, const struct PlayerData& p, bool isSelf);
};

// Synchronous bothax hook bridge — called from hook.cpp packet paths while
// holding g_LuaMtx; a `true` return means "a hook returned true".
namespace LuaHooks {
    bool dispatchVariant(const std::string& text);            // OnVariant
    bool dispatchSendPacket(int ptype, const std::string& text); // OnSendPacket
    bool dispatchSendPacketRaw(const void* data, int len);     // OnSendPacketRaw
    // replay events parked by try-lock contention (must hold g_LuaMtx)
    void drainPending();
}
