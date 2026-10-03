#include "lua_api.h"
#include "hook.h"
#include "scanner.h"
#include "itemdb.h"
#include <lua.h>
#include <lauxlib.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <windows.h>
#include <unordered_map>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

std::mutex g_consoleMutex;
std::deque<LogEntry> g_consoleLogs;
std::mutex g_debugMutex;
std::deque<LogEntry> g_debugLogs;
std::recursive_mutex g_LuaMtx;
static FILE* g_logFile = nullptr;
static std::mutex g_fileMtx;

static void WriteToFile(const std::string& msg) {
    std::lock_guard<std::mutex> fl(g_fileMtx);
    if (!g_logFile) {
        static const char kPath[] =
            "C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\package-scanner-output\\Cmd Log\\log.txt";
        static const char kOld[] =
            "C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\package-scanner-output\\Cmd Log\\log.txt.old";
        // rotate an oversized log instead of letting it grow unbounded
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExA(kPath, GetFileExInfoStandard, &fad) &&
            fad.nFileSizeHigh == 0 && fad.nFileSizeLow > (32u << 20)) {
            MoveFileExA(kPath, kOld, MOVEFILE_REPLACE_EXISTING);
        }
        // append (not truncate): GT and CG share this file — a boot in one
        // process must not wipe the other's dumps
        g_logFile = fopen(kPath, "a");
        if (g_logFile) {
            static char s_pid[16] = {};
            if (!s_pid[0])
                snprintf(s_pid, sizeof s_pid, "%lu",
                         (unsigned long)GetCurrentProcessId());
            fprintf(g_logFile, "[%s] ---- log open ----\n", s_pid);
            fflush(g_logFile);
        }
    }
    if (g_logFile) {
        static char s_pid[16] = {};
        if (!s_pid[0])
            snprintf(s_pid, sizeof s_pid, "%lu",
                     (unsigned long)GetCurrentProcessId());
        fprintf(g_logFile, "[%s] %s\n", s_pid, msg.c_str());
        fflush(g_logFile);
    }
}

void writeFileLog(const std::string& msg) { WriteToFile(msg); }

void consoleLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_consoleMutex);
    g_consoleLogs.push_back({msg, g_currentTime});
    if (g_consoleLogs.size() > 500) g_consoleLogs.erase(g_consoleLogs.begin());
    WriteToFile(msg);
}

// ── async walk machinery ─────────────────────────────────────────────
// FindPath(x, y) (2-arg, tile coords) starts an async walk stepped once
// per render tick; the calling Lua coroutine yields until arrival, giving
// GrowPai blocking semantics without blocking the event pump.
// Lock order is always g_WalkMtx BEFORE GameState::mtx.
namespace {
struct WalkState {
    bool active = false;
    bool failed = false;
    float x = 0, y = 0;
    float tx = 0, ty = 0;
    DWORD lastStep = 0;
    int steps = 0;
};
WalkState g_Walk;
std::mutex g_WalkMtx;

// tank type-0 state packet (56-byte PlayerMoving, sent as msg type 4)
void SendStatePacket(float x, float y) {
    auto& gs = GameState::instance();
    int32_t netid = -1, state = 0;
    {
        std::lock_guard<std::mutex> gl(gs.mtx);
        netid = gs.localPlayer.netid;
        state = gs.localPlayer.flags;
    }
    unsigned char p[56];
    memset(p, 0, sizeof p);
    int32_t sec = -1;
    memcpy(p + 4, &netid, 4);
    memcpy(p + 8, &sec, 4);
    memcpy(p + 12, &state, 4);
    memcpy(p + 24, &x, 4);
    memcpy(p + 28, &y, 4);
    scanner::CallSendPacketBin(4, p, sizeof p);
}
} // namespace

static void WalkStep() {
    std::lock_guard<std::mutex> lk(g_WalkMtx);
    if (!g_Walk.active) return;
    DWORD now = GetTickCount();
    if (g_Walk.lastStep != 0 && now - g_Walk.lastStep < 30) return;
    g_Walk.lastStep = now;
    float dx = g_Walk.tx - g_Walk.x;
    float dy = g_Walk.ty - g_Walk.y;
    auto& gs = GameState::instance();
    if (dx <= 4 && dx >= -4 && dy <= 4 && dy >= -4) {
        g_Walk.x = g_Walk.tx;
        g_Walk.y = g_Walk.ty;
        SendStatePacket(g_Walk.x, g_Walk.y);
        {
            std::lock_guard<std::mutex> gl(gs.mtx);
            gs.localPlayer.pos_x = g_Walk.x;
            gs.localPlayer.pos_y = g_Walk.y;
            gs.localPlayer.tile_x = (int)(g_Walk.x / 32);
            gs.localPlayer.tile_y = (int)(g_Walk.y / 32);
        }
        if (g_Walk.steps > 2)
            consoleLog("[WALK] arrived (" + std::to_string((int)(g_Walk.x / 32)) +
                       "," + std::to_string((int)(g_Walk.y / 32)) + ")");
        g_Walk.active = false;
        return;
    }
    const float step = 4.0f;
    g_Walk.x += (dx > step) ? step : (dx < -step ? -step : dx);
    g_Walk.y += (dy > step) ? step : (dy < -step ? -step : dy);
    if (++g_Walk.steps > 900) { // ~27 s wall cap
        consoleLog("[WALK] FAILED: step cap at target (" +
                   std::to_string((int)(g_Walk.tx / 32)) + "," +
                   std::to_string((int)(g_Walk.ty / 32)) + ")");
        g_Walk.active = false;
        g_Walk.failed = true;
        return;
    }
    if (g_Walk.steps % 100 == 0) {
        int32_t nid = -1;
        {
            std::lock_guard<std::mutex> gl(gs.mtx);
            nid = gs.localPlayer.netid;
        }
        consoleLog("[WALK] step " + std::to_string(g_Walk.steps) +
                   " pos=(" + std::to_string((int)g_Walk.x) + "," +
                   std::to_string((int)g_Walk.y) + ") netid=" +
                   std::to_string(nid));
    }
    SendStatePacket(g_Walk.x, g_Walk.y);
    {
        std::lock_guard<std::mutex> gl(gs.mtx);
        gs.localPlayer.pos_x = g_Walk.x;
        gs.localPlayer.pos_y = g_Walk.y;
        gs.localPlayer.tile_x = (int)(g_Walk.x / 32);
        gs.localPlayer.tile_y = (int)(g_Walk.y / 32);
    }
}

// continuation: re-yield every 30 ms while the walk is in progress
static int walk_wait_cont(lua_State* L, int status, lua_KContext ctx) {
    (void)status; (void)ctx;
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    bool active = false, failed = false;
    {
        std::lock_guard<std::mutex> lk(g_WalkMtx);
        active = g_Walk.active;
        failed = g_Walk.failed;
    }
    if (active) {
        if (self) {
            float rt = g_currentTime + 0.03f;
            for (auto& t : self->threads)
                if (t.co == L) { t.resumeTime = rt; break; }
        }
        lua_yieldk(L, 0, 0, walk_wait_cont);
        return 0;
    }
    lua_pushboolean(L, failed ? 0 : 1);
    return 1;
}

LuaExecutor::LuaExecutor() {
    L = luaL_newstate();
    luaL_openlibs(L);
    lua_pushlightuserdata(L, this);
    lua_setfield(L, LUA_REGISTRYINDEX, "__executor");
    registerAPI();
}

LuaExecutor::~LuaExecutor() { if (L) lua_close(L); }

// keep the spy_ptup tank-event gate in sync with registered callbacks
static void rescanTankFlag(const std::vector<CallbackInfo>& cbs) {
    bool any = false;
    for (auto& cb : cbs)
        if (cb.type == "OnTankPacket") { any = true; break; }
    g_OnTankPacket.store(any);
}

// snapshot of callback refs for one event type — dispatch loops must not
// iterate `callbacks` by iterator: a pcall'd handler may AddHook/RemoveHook
// (reallocating the vector) and Debug CRT asserts "can't increment
// invalidated vector iterator". Refs resolve to nil if removed meanwhile.
static std::vector<int> snapRefs(const std::vector<CallbackInfo>& cbs,
                                 const std::string& type) {
    std::vector<int> refs;
    for (auto& cb : cbs)
        if (cb.type == type) refs.push_back(cb.ref);
    return refs;
}

bool LuaExecutor::execute(const std::string& script) {
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    if (running) stop();
    running = true;
    startTime = g_currentTime;
    callbacks.clear();
    timers.clear();
    threads.clear();
    commands.clear();
    delayed.clear();
    rescanTankFlag(callbacks);
    lastTickTime = g_currentTime;
    int err = luaL_loadstring(L, script.c_str());
    if (err) {
        const char* errmsg = lua_tostring(L, -1);
        consoleLog("[ERROR] " + std::string(errmsg ? errmsg : "(non-string error object)"));
        lua_pop(L, 1);
        running = false;
        return false;
    }
    // Run the main chunk inside a coroutine: bothax scripts use top-level
    // Sleep()/FindPath() which yield — yielding across lua_pcall would be
    // "attempt to yield from outside a coroutine".
    lua_State* co = lua_newthread(L);           // [fn]
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);   // pops thread
    lua_pushvalue(L, -1);                       // [fn fn']
    lua_xmove(L, co, 1);                        // co: [fn']
    // register BEFORE first resume so lua_Sleep can find the resume slot
    threads.push_back({co, g_currentTime, ref});
    int nres = 0;
    int status = lua_resume(co, L, 0, &nres);
    auto dropThread = [&]() {
        for (auto it = threads.begin(); it != threads.end(); ++it)
            if (it->co == co) { threads.erase(it); break; }
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    };
    if (status == LUA_OK) {
        lua_settop(co, 0);
        dropThread();
    } else if (status != LUA_YIELD) {
        const char* errmsg = lua_tostring(co, -1);
        consoleLog("[ERROR] " + std::string(errmsg ? errmsg : "(non-string error object)"));
        lua_pop(co, 1);
        dropThread();
        running = false;
        lua_pop(L, 1); // leftover fn
        return false;
    }
    lua_pop(L, 1); // leftover fn
    consoleLog("[INFO] Script executed. Callbacks/timers dispatched from render hook.");
    return true;
}

void LuaExecutor::tick(float dt) {
    if (!running || !L) return;
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    LuaHooks::drainPending();   // replay events parked under lock contention
    float now = g_currentTime;
    lastTickTime = now;

    WalkStep(); // advance any active FindPath walk (sends state packets)

    // Resume sleeping threads. Index-based: lua_resume re-enters script code
    // which may call startThread()/RunThread() — those push_back into
    // `threads` (possible reallocation), invalidating any live iterator
    // (Debug CRT: "can't increment invalidated vector iterator" wedge).
    for (size_t i = 0; i < threads.size(); ) {
        if (now >= threads[i].resumeTime) {
            int nres;
            int status = lua_resume(threads[i].co, L, 0, &nres);
            if (status == LUA_OK) {
                luaL_unref(L, LUA_REGISTRYINDEX, threads[i].ref);
                threads.erase(threads.begin() + i);
            } else if (status == LUA_YIELD) {
                ++i;
            } else {
                const char* errmsg = lua_tostring(threads[i].co, -1);
                consoleLog("[ERROR] Thread: " + std::string(errmsg ? errmsg : "(non-string error object)"));
                lua_pop(threads[i].co, 1);
                luaL_unref(L, LUA_REGISTRYINDEX, threads[i].ref);
                threads.erase(threads.begin() + i);
            }
        } else { ++i; }
    }

    // Dispatch OnUpdate callbacks
    for (int ref : snapRefs(callbacks, "OnUpdate")) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        if (!lua_isfunction(L, -1)) { lua_pop(L, 1); continue; }
        lua_pushnumber(L, dt);
        if (lua_pcall(L, 1, 1, 0) != 0) { lua_pop(L, 1); } else { lua_pop(L, 1); }
    }

    // bothax OnDraw(deltatime) — dispatched from the render hook
    for (int ref : snapRefs(callbacks, "OnDraw")) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        if (!lua_isfunction(L, -1)) { lua_pop(L, 1); continue; }
        lua_pushnumber(L, dt);
        if (lua_pcall(L, 1, 1, 0) != 0) { lua_pop(L, 1); } else { lua_pop(L, 1); }
    }

    // Dispatch packet events
    PacketEvent ev;
    while (GameState::instance().popEvent(ev)) {
        // NPC tracking for bothax GetNPCList/GetNPC (tank type 34; low byte
        // only — the u32 at tank+0 also carries netid/count bytes)
        if (ev.type == "OnTankPacket" && (ev.packet_type & 0xFF) == 34) {
            auto& gs = GameState::instance();
            std::lock_guard<std::mutex> gl(gs.mtx);
            NPCData* found = nullptr;
            for (auto& n : gs.npcs) if (n.id == ev.netid) { found = &n; break; }
            if (!found) { gs.npcs.push_back({}); found = &gs.npcs.back(); }
            found->id = ev.netid;
            found->type = ev.flags;
            found->pos_x = ev.pos_x;
            found->pos_y = ev.pos_y;
            // target = struct +44/+48 (px/py ints); falls back to int_data
            // for x when the py pair is zero (mapping unverified live)
            if (ev.pos2_x != 0 || ev.pos2_y != 0) {
                found->target_x = ev.pos2_x;
                found->target_y = ev.pos2_y;
            } else {
                found->target_x = (float)ev.int_data;
            }
        }
        std::string cmdName, cmdArgs;
        if (ev.type == "OnCommand") {
            std::string t = ev.text;
            if (!t.empty() && t[0] == '/') t.erase(0, 1);
            size_t sp = t.find(' ');
            cmdName = (sp == std::string::npos) ? t : t.substr(0, sp);
            cmdArgs = (sp == std::string::npos) ? "" : t.substr(sp + 1);
            auto cit = commands.find(cmdName);
            if (cit != commands.end()) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, cit->second);
                lua_pushstring(L, cmdArgs.c_str());
                if (lua_pcall(L, 1, 1, 0) != 0) {
                    const char* err = lua_tostring(L, -1);
                    consoleLog("[ERROR] /" + cmdName + ": " + (err ? err : "?"));
                    lua_pop(L, 1);
                } else {
                    lua_pop(L, 1);
                }
                continue;
            }
        }
        for (int ref : snapRefs(callbacks, ev.type)) {
            {
                lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
                if (!lua_isfunction(L, -1)) { lua_pop(L, 1); continue; }
                if (ev.type == "OnVarlist") {
                    lua_newtable(L);
                    std::istringstream stream(ev.text);
                    std::string line;
                    int idx = 0;
                    while (std::getline(stream, line)) {
                        size_t pipe = line.find('|');
                        std::string key, val;
                        if (pipe != std::string::npos) { key = line.substr(0, pipe); val = line.substr(pipe + 1); }
                        else { key = std::to_string(idx); val = line; }
                        lua_pushstring(L, val.c_str()); lua_setfield(L, -2, key.c_str());
                        lua_pushstring(L, val.c_str()); lua_rawseti(L, -2, idx);
                        idx++;
                    }
                    lua_pushstring(L, ev.text.c_str());
                    if (lua_pcall(L, 2, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                } else if (ev.type == "OnPacket") {
                    // GrowPai signature: callback(type, dataString) —
                    // coems_suite's onPacket(ptype, packet) requires the raw
                    // text as a string, not a table.
                    lua_pushinteger(L, ev.packet_type);
                    lua_pushstring(L, ev.text.c_str());
                    if (lua_pcall(L, 2, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                } else if (ev.type == "OnTankPacket") {
                    // GrowPai onprocesstankupdatepacket: callback(packet)
                    // packet.type / packet.xspeed drive the geiger ring
                    lua_newtable(L);
                    lua_pushinteger(L, ev.packet_type); lua_setfield(L, -2, "type");
                    lua_pushinteger(L, ev.netid); lua_setfield(L, -2, "netid");
                    lua_pushinteger(L, ev.flags); lua_setfield(L, -2, "flags");
                    lua_pushinteger(L, ev.int_data); lua_setfield(L, -2, "int_data");
                    lua_pushnumber(L, ev.pos_x); lua_setfield(L, -2, "x");
                    lua_pushnumber(L, ev.pos_y); lua_setfield(L, -2, "y");
                    lua_pushnumber(L, ev.pos_x); lua_setfield(L, -2, "pos_x");
                    lua_pushnumber(L, ev.pos_y); lua_setfield(L, -2, "pos_y");
                    lua_pushnumber(L, ev.xspeed); lua_setfield(L, -2, "xspeed");
                    lua_pushnumber(L, ev.yspeed); lua_setfield(L, -2, "yspeed");
                    if (lua_pcall(L, 1, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                } else if (ev.type == "OnCommand") {
                    lua_pushstring(L, cmdName.c_str());
                    lua_pushstring(L, cmdArgs.c_str());
                    if (lua_pcall(L, 2, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                } else {
                    lua_newtable(L);
                    lua_pushinteger(L, ev.packet_type); lua_setfield(L, -2, "type");
                    lua_pushinteger(L, ev.netid); lua_setfield(L, -2, "netid");
                    lua_pushinteger(L, ev.flags); lua_setfield(L, -2, "flags");
                    lua_pushinteger(L, ev.item); lua_setfield(L, -2, "item");
                    lua_pushnumber(L, ev.pos_x); lua_setfield(L, -2, "pos_x");
                    lua_pushnumber(L, ev.pos_y); lua_setfield(L, -2, "pos_y");
                    lua_pushstring(L, ev.text.c_str()); lua_setfield(L, -2, "data");
                    if (lua_pcall(L, 1, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                }
            }
        }
    }

    // bothax OnWorldTouch(pos, start) — fire when the local player's tile changes
    {
        static int s_LastTx = -9999, s_LastTy = -9999;
        int tx = 0, ty = 0;
        float px = 0, py = 0;
        {
            auto& gs = GameState::instance();
            std::lock_guard<std::mutex> gl(gs.mtx);
            tx = gs.localPlayer.tile_x;
            ty = gs.localPlayer.tile_y;
            px = gs.localPlayer.pos_x;
            py = gs.localPlayer.pos_y;
        }
        if (tx != s_LastTx || ty != s_LastTy) {
            bool had = (s_LastTx != -9999);
            if (had) {
                for (int ref : snapRefs(callbacks, "OnWorldTouch")) {
                    {
                        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
                        lua_newtable(L);
                        lua_pushnumber(L, px); lua_setfield(L, -2, "x");
                        lua_pushnumber(L, py); lua_setfield(L, -2, "y");
                        lua_pushboolean(L, 0);   // start = false → left the tile
                        if (lua_pcall(L, 2, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                    }
                }
            }
            s_LastTx = tx; s_LastTy = ty;
            // enter the new tile: start = true
            for (int ref : snapRefs(callbacks, "OnWorldTouch")) {
                {
                    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
                    lua_newtable(L);
                    lua_pushnumber(L, px); lua_setfield(L, -2, "x");
                    lua_pushnumber(L, py); lua_setfield(L, -2, "y");
                    lua_pushboolean(L, 1);
                    if (lua_pcall(L, 2, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                }
            }
        }
    }

    // bothax OnInput(key) — VK-code edge detect (windows-only per docs).
    // VK codes match ASCII for alnum so string.char(key) works for letters.
    {
        static bool s_Prev[256] = {};
        std::vector<int> inRefs = snapRefs(callbacks, "OnInput");
        if (!inRefs.empty()) {
            for (int vk = 1; vk < 256; vk++) {
                bool down = (GetAsyncKeyState(vk) & 0x8000) != 0;
                if (down && !s_Prev[vk]) {
                    for (int ref : inRefs) {
                        {
                            lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
                            if (!lua_isfunction(L, -1)) { lua_pop(L, 1); continue; }
                            lua_pushinteger(L, vk);
                            if (lua_pcall(L, 1, 1, 0) != 0) lua_pop(L, 1); else lua_pop(L, 1);
                        }
                    }
                }
                s_Prev[vk] = down;
            }
        }
    }

    // bothax RunDelayed(ms, fn, ...) — fire pending one-shots with args.
    // Index-based + erase-before-pcall: the handler may call RunDelayed()
    // again (push_back → reallocation), so no iterator/reference may survive
    // the pcall.
    for (size_t i = 0; i < delayed.size(); ) {
        if (now >= delayed[i].fireAt) {
            int ref = delayed[i].ref;
            std::vector<int> argRefs = delayed[i].argRefs;
            delayed.erase(delayed.begin() + i);
            int nargs = (int)argRefs.size();
            lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
            for (int k = 0; k < nargs; k++) lua_rawgeti(L, LUA_REGISTRYINDEX, argRefs[k]);
            if (lua_pcall(L, nargs, 1, 0) != 0) {
                const char* err = lua_tostring(L, -1);
                consoleLog("[ERROR] RunDelayed: " + std::string(err ? err : "?"));
                lua_pop(L, 1);
            } else {
                lua_pop(L, 1);
            }
            luaL_unref(L, LUA_REGISTRYINDEX, ref);
            for (int r : argRefs) luaL_unref(L, LUA_REGISTRYINDEX, r);
            continue;   // next entry shifted into slot i
        } else { ++i; }
    }

    // Tick timers — same realloc hazard: a timer callback may AddTimer.
    for (size_t i = 0; i < timers.size(); ) {
        if (now - timers[i].lastTick >= timers[i].interval) {
            timers[i].lastTick = now;
            int ref = timers[i].ref;
            int repeat = timers[i].repeat;
            if (repeat > 0) timers[i].repeat = repeat - 1;
            lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
            if (lua_pcall(L, 0, 0, 0) != 0) { lua_pop(L, 1); }
            if (i < timers.size() && timers[i].ref == ref) {
                if (repeat > 0 && repeat - 1 == 0) {
                    luaL_unref(L, LUA_REGISTRYINDEX, ref);
                    timers.erase(timers.begin() + i);
                    continue;
                }
                ++i;
            }
            // else: handler removed this timer — next entry sits at i
        } else { ++i; }
    }
}

void LuaExecutor::stop() {
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    running = false;
    if (L) lua_close(L);
    L = luaL_newstate(); luaL_openlibs(L);
    lua_pushlightuserdata(L, this); lua_setfield(L, LUA_REGISTRYINDEX, "__executor");
    registerAPI(); callbacks.clear(); timers.clear(); threads.clear(); commands.clear(); delayed.clear();
    rescanTankFlag(callbacks);
    {
        std::lock_guard<std::mutex> lk(g_WalkMtx);
        g_Walk.active = false;
        g_Walk.failed = true;
    }
}

int LuaExecutor::lua_log(lua_State* L) { consoleLog("[LUA] " + std::string(luaL_checkstring(L, 1))); return 0; }
int LuaExecutor::lua_SendPacket(lua_State* L) {
    int type = (int)luaL_checkinteger(L, 1);
    const char* text = luaL_checkstring(L, 2);
    debugLog("[PACKET] SendPacket type=" + std::to_string(type));
    scanner::CallSendPacket(type, text ? text : "");
    return 0;
}

int LuaExecutor::lua_SendPacketRaw(lua_State* L) {
    if (lua_isboolean(L, 1)) return lua_SendPacketRawBx(L); // bothax (bool, table)
    const char* data = luaL_checkstring(L, 1);              // legacy (string, len)
    int len = (int)luaL_optinteger(L, 2, 0);
    if (!data || len <= 0) return 0;
    int type = (data[0] & 0xFF);
    scanner::CallSendPacket(type, data + 4);
    debugLog("[PACKET] SendPacketRaw len=" + std::to_string(len));
    return 0;
}

int LuaExecutor::lua_SendVarlist(lua_State* L) {
    if (lua_gettop(L) < 1) return 0;
    std::string result;
    if (lua_istable(L, 1)) {
        int n = (int)lua_rawlen(L, 1);
        for (int i = 1; i <= n; i++) {
            lua_rawgeti(L, 1, i);
            if (lua_isstring(L, -1)) {
                result += lua_tostring(L, -1);
                result += "\n";
            }
            lua_pop(L, 1);
        }
    } else if (lua_isstring(L, 1)) {
        result = lua_tostring(L, 1);
    }
    if (!result.empty()) {
        debugLog("[PACKET] SendVarlist: " + result.substr(0, 100));
        scanner::CallSendPacket(4, result.c_str());
    }
    return 0;
}

// ── live gems ───────────────────────────────────────────────────────────────
// Break-gems are credited client-side with NO OnSetBux packet, so the packet
// value (localPlayer.gems) lags the HUD. The game keeps the live balance in
// (at least) two identical heap copies. Find them with an equal-pair scan in
// a window around the last known value; static pairs (thousands of id/table
// junk pairs live nearby) are rejected by observing the pair across two scan
// passes — only the real balance changes in lockstep while earning. Cached
// addresses are re-read on the fast path (2 ReadProcessMemory calls); a full
// rescan only happens if the pair breaks. Runs before the GameState lock.
static void LiveGemsScanWindow(uint32_t lo, uint32_t hi,
    std::unordered_map<uintptr_t, std::pair<uintptr_t, uint32_t>>& out) {
    out.clear();
    std::unordered_map<uint32_t, std::pair<uintptr_t, uintptr_t>> hits;
    MEMORY_BASIC_INFORMATION mbi;
    for (uint8_t* addr = nullptr;
         VirtualQuery(addr, &mbi, sizeof mbi);
         addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
        DWORD pr = mbi.Protect & 0xFF;
        bool wr = pr == 0x02 || pr == 0x04 || pr == 0x08 || pr == 0x40 || pr == 0x80;
        if (!wr || (mbi.Protect & PAGE_GUARD)) continue;
        uint32_t* p = (uint32_t*)mbi.BaseAddress;
        size_t cnt = mbi.RegionSize / 4;
        for (size_t i = 0; i < cnt; i++) {
            uint32_t v = p[i];
            if (v < lo || v > hi) continue;
            auto it = hits.find(v);
            if (it == hits.end())
                hits.emplace(v, std::make_pair((uintptr_t)&p[i], (uintptr_t)0));
            else if (it->second.second == 0)
                it->second.second = (uintptr_t)&p[i];
        }
    }
    for (auto& kv : hits)
        if (kv.second.second)
            out.emplace(kv.second.first, std::make_pair(kv.second.second, kv.first));
}

static uint32_t LiveGemsPoll(uint32_t packetGems) {
    static uint32_t s_a = 0, s_b = 0, s_last = 0, s_floor = 0;
    static DWORD s_scanAt = 0;
    static int s_attempt = 0;
    if (packetGems > 1000) {
        uint32_t fl = packetGems - packetGems / 4;
        if (fl > s_floor) s_floor = fl;
    }
    auto read32 = [](uintptr_t addr, uint32_t& v) -> bool {
        SIZE_T n = 0;
        return ReadProcessMemory(GetCurrentProcess(), (void*)addr, &v, 4, &n) && n == 4;
    };
    // fast path: wallet counter lives in game ctx at +0x2D0 (client-side,
    // updated on every break; equals what the HUD shows)
    if (scanner::fn_GetCtx) {
        typedef uintptr_t (*GetCtx_t)();
        uintptr_t ctx = ((GetCtx_t)scanner::fn_GetCtx)();
        if (ctx) {
            uint32_t v = 0;
            SIZE_T n = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void*)(ctx + 0x2D0), &v, 4, &n) &&
                n == 4 && v && v < 2000000000u) {
                bool ok = false;
                if (packetGems > 1000) {
                    uint32_t fl = packetGems - packetGems / 4;
                    if (v >= fl || v >= packetGems) ok = true;
                }
                if (!ok && s_last && v >= s_last) ok = true;
                if (ok) {
                    s_a = 0;
                    s_b = 0;
                    s_last = v;
                    s_attempt = 0;
                    static int s_ctxLogged = 0;
                    if (s_ctxLogged < 3) {
                        s_ctxLogged++;
                        debugLog("[LIVEGEMS] ctx+0x2D0 = " + std::to_string(v));
                    }
                    return v;
                }
            }
        }
    }
    if (s_a && s_b) {
        uint32_t va = 0, vb = 0;
        if (read32(s_a, va) && read32(s_b, vb) && va == vb &&
            va >= s_floor && va <= 2000000000u) {
            s_last = va;
            return va;
        }
    }
    DWORD now = GetTickCount();
    DWORD gap = 3000;
    for (int i = 0; i < s_attempt / 3 && gap < 15000; i++) gap *= 2;
    if (s_attempt >= 3 && s_last) gap = 15000;
    if (s_attempt && now - s_scanAt < gap)
        return s_last ? s_last : packetGems;
    s_scanAt = now;
    s_attempt++;

    uint32_t target = s_last ? s_last : packetGems;
    if (!target) return 0;
    uint32_t lo = target > 5000000u ? target - 5000000u : 0;
    if (s_floor > lo) lo = s_floor;
    uint32_t hi = target + 50000000u;
    if (hi < target) hi = 0xFFFFFFFFu;

    std::unordered_map<uintptr_t, std::pair<uintptr_t, uint32_t>> pass1, pass2;
    LiveGemsScanWindow(lo, hi, pass1);
    Sleep(350);
    LiveGemsScanWindow(lo, hi, pass2);

    uint32_t best = 0, bestDist = 0xFFFFFFFFu;
    uintptr_t ba = 0, bb = 0;
    for (auto& kv : pass2) {
        auto it = pass1.find(kv.first);
        if (it == pass1.end()) continue;
        if (it->second.first != kv.second.first) continue;   // other copy moved
        if (it->second.second == kv.second.second) continue; // unchanged = junk
        uint32_t v = kv.second.second;
        uint32_t d = v > target ? v - target : target - v;
        if (d < bestDist) {
            bestDist = d;
            best = v;
            ba = kv.first;
            bb = kv.second.first;
        }
    }
    if (best) {
        s_a = (uint32_t)ba;
        s_b = (uint32_t)bb;
        s_last = best;
        s_attempt = 0;
        static int s_foundLogged = 0;
        if (s_foundLogged < 5) {
            s_foundLogged++;
            debugLog("[LIVEGEMS] locked pair 0x" + std::to_string(ba) + "/0x" +
                     std::to_string(bb) + " = " + std::to_string(best));
        }
        return best;
    }
    if (!s_last && packetGems) s_last = packetGems;
    return s_last;
}

int LuaExecutor::lua_GetLocal(lua_State* L) {
    auto& gs = GameState::instance();
    uint32_t packetGems = 0;
    {
        std::lock_guard<std::mutex> lk(gs.mtx);
        packetGems = (uint32_t)gs.localPlayer.gems;
    }
    uint32_t liveGems = LiveGemsPoll(packetGems);
    std::lock_guard<std::mutex> lock(gs.mtx);
    auto& p = gs.localPlayer;
    {
        static int s_GetLocalLogged = 0;
        if (s_GetLocalLogged < 8) {
            s_GetLocalLogged++;
            debugLog("[PLAYER] GetLocal: name=" + p.name + " world=" + p.world + " gems=" + std::to_string(p.gems));
        }
    }
    lua_newtable(L);
    lua_pushstring(L, p.name.c_str()); lua_setfield(L, -2, "name");
    lua_pushstring(L, p.world.c_str()); lua_setfield(L, -2, "world");
    lua_pushstring(L, p.country.c_str()); lua_setfield(L, -2, "country");
    lua_pushnumber(L, p.pos_x); lua_setfield(L, -2, "pos_x");
    lua_pushnumber(L, p.pos_y); lua_setfield(L, -2, "pos_y");
    lua_pushinteger(L, p.tile_x); lua_setfield(L, -2, "tile_x");
    lua_pushinteger(L, p.tile_y); lua_setfield(L, -2, "tile_y");
    lua_pushnumber(L, p.size_x); lua_setfield(L, -2, "size_x");
    lua_pushnumber(L, p.size_y); lua_setfield(L, -2, "size_y");
    lua_pushinteger(L, p.netid); lua_setfield(L, -2, "netid");
    lua_pushinteger(L, p.userid); lua_setfield(L, -2, "userid");
    lua_pushinteger(L, liveGems ? (lua_Integer)liveGems : p.gems); lua_setfield(L, -2, "gems");
    lua_pushboolean(L, p.facing_left); lua_setfield(L, -2, "facing_left");
    lua_pushboolean(L, p.facing_left); lua_setfield(L, -2, "isleft");
    lua_pushboolean(L, p.invisible); lua_setfield(L, -2, "invisible");
    lua_pushboolean(L, p.mstate); lua_setfield(L, -2, "mstate");
    lua_pushboolean(L, p.smstate); lua_setfield(L, -2, "smstate");
    lua_pushinteger(L, p.flags); lua_setfield(L, -2, "flags");
    lua_pushinteger(L, p.flags2); lua_setfield(L, -2, "flags2");
    // nested pos table — GrowPai GetLocal().pos.x / .pos.y
    lua_newtable(L);
    lua_pushnumber(L, p.pos_x); lua_setfield(L, -2, "x");
    lua_pushnumber(L, p.pos_y); lua_setfield(L, -2, "y");
    lua_setfield(L, -2, "pos");
    return 1;
}

int LuaExecutor::lua_GetInventory(lua_State* L) {
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& item : gs.inventory) {
        lua_newtable(L);
        lua_pushinteger(L, item.id); lua_setfield(L, -2, "id");
        lua_pushinteger(L, item.count); lua_setfield(L, -2, "count");
        lua_pushinteger(L, item.count); lua_setfield(L, -2, "amount");
        lua_pushinteger(L, item.flags); lua_setfield(L, -2, "flags");
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_GetPlayers(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& p : gs.players) {
        pushAvatar(L, p, false);
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_GetObjects(lua_State* L) {
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& obj : gs.objects) {
        lua_newtable(L);
        lua_pushinteger(L, obj.id); lua_setfield(L, -2, "id");
        lua_pushinteger(L, obj.oid); lua_setfield(L, -2, "oid");
        lua_pushnumber(L, obj.pos_x); lua_setfield(L, -2, "pos_x");
        lua_pushnumber(L, obj.pos_y); lua_setfield(L, -2, "pos_y");
        lua_pushinteger(L, obj.count); lua_setfield(L, -2, "count");
        lua_pushinteger(L, obj.count); lua_setfield(L, -2, "amount");
        lua_pushinteger(L, obj.flags); lua_setfield(L, -2, "flags");
        lua_newtable(L);
        lua_pushnumber(L, obj.pos_x); lua_setfield(L, -2, "x");
        lua_pushnumber(L, obj.pos_y); lua_setfield(L, -2, "y");
        lua_setfield(L, -2, "pos");
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

// shared Tile table builder — caller must hold gs.mtx (reads itemDatabase)
void LuaExecutor::pushTileCommon(lua_State* L, const TileData& t, int x, int y, bool inBounds) {
    lua_newtable(L);
    lua_pushinteger(L, t.fg); lua_setfield(L, -2, "fg");
    lua_pushinteger(L, t.bg); lua_setfield(L, -2, "bg");
    bool coll = (t.fg != 0);
    int coltype = 0;
    if (t.fg != 0) {
        auto it = GameState::instance().itemDatabase.find(t.fg);
        if (it != GameState::instance().itemDatabase.end()) {
            coltype = it->second.coltype;
            coll = (coltype != 0);   // items.dat CollisionType: 0 = passable
        }
    }
    lua_pushboolean(L, inBounds && coll); lua_setfield(L, -2, "collidable");
    lua_pushinteger(L, x); lua_setfield(L, -2, "x");
    lua_pushinteger(L, y); lua_setfield(L, -2, "y");
    lua_pushinteger(L, x); lua_setfield(L, -2, "pos_x");   // legacy aliases
    lua_pushinteger(L, y); lua_setfield(L, -2, "pos_y");
    lua_pushinteger(L, coltype); lua_setfield(L, -2, "coltype");
    lua_pushboolean(L, (t.flags & 0x4000) != 0); lua_setfield(L, -2, "locktile");
    lua_pushinteger(L, t.flags); lua_setfield(L, -2, "flags_value"); // raw int
    pushTileFlags(L, t.flags); lua_setfield(L, -2, "flags");
    // extra: nil when 0, else minimal TileExtra table (raw word kept too)
    lua_pushinteger(L, t.extra); lua_setfield(L, -2, "extra_value");
    if (t.extra != 0) {
        lua_newtable(L);
        lua_pushinteger(L, t.extra & 0xFF); lua_setfield(L, -2, "type");
        lua_pushinteger(L, t.extra); lua_setfield(L, -2, "flags");
        lua_pushinteger(L, 0); lua_setfield(L, -2, "progress");
        lua_pushstring(L, ""); lua_setfield(L, -2, "label");
        lua_pushinteger(L, 0); lua_setfield(L, -2, "owner");
        lua_setfield(L, -2, "extra");
    } else {
        lua_pushnil(L); lua_setfield(L, -2, "extra");
    }
    lua_pushboolean(L, t.water || (t.flags & 0x100) != 0); lua_setfield(L, -2, "water");
    lua_pushboolean(L, t.fire); lua_setfield(L, -2, "fire");
    lua_pushboolean(L, t.ready); lua_setfield(L, -2, "ready");
}

int LuaExecutor::lua_GetTile(lua_State* L) {
    int x = (int)luaL_checkinteger(L, 1);
    int y = (int)luaL_checkinteger(L, 2);
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    bool inB = (x >= 0 && x < gs.world_size_x && y >= 0 && y < gs.world_size_y &&
                !gs.tiles.empty() && y < (int)gs.tiles.size() && x < (int)gs.tiles[y].size());
    TileData td;
    if (inB) td = gs.tiles[y][x];
    pushTileCommon(L, td, x, y, inB);
    return 1;
}

int LuaExecutor::lua_GetTiles(lua_State* L) {
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (int y = 0; y < gs.world_size_y && y < (int)gs.tiles.size(); y++) {
        for (int x = 0; x < gs.world_size_x && x < (int)gs.tiles[y].size(); x++) {
            pushTileCommon(L, gs.tiles[y][x], x, y, true);
            lua_rawseti(L, -2, idx++);
        }
    }
    return 1;
}
int LuaExecutor::lua_FindPath(lua_State* L) {
    if (lua_gettop(L) == 2) {
        // GrowPai form: FindPath(tileX, tileY) — walk the local player to
        // the tile center, yielding until arrival (or ~20 s timeout).
        int endX = (int)luaL_checkinteger(L, 1);
        int endY = (int)luaL_checkinteger(L, 2);
        float tx = endX * 32.0f + 16.0f;
        float ty = endY * 32.0f + 16.0f;
        LuaExecutor* self = nullptr;
        lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
        if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
        lua_pop(L, 1);
        {
            std::lock_guard<std::mutex> lk(g_WalkMtx);
            auto& gs = GameState::instance();
            float sx = 0, sy = 0;
            int nid = -1;
            {
                std::lock_guard<std::mutex> gl(gs.mtx);
                sx = gs.localPlayer.pos_x;
                sy = gs.localPlayer.pos_y;
                nid = gs.localPlayer.netid;
            }
            if (tx - sx <= 6 && tx - sx >= -6 && ty - sy <= 6 && ty - sy >= -6) {
                lua_pushboolean(L, 1); // already there
                return 1;
            }
            g_Walk.active = true;
            g_Walk.failed = false;
            g_Walk.x = sx; g_Walk.y = sy;
            g_Walk.tx = tx; g_Walk.ty = ty;
            g_Walk.lastStep = 0;
            g_Walk.steps = 0;
            consoleLog("[WALK] start (" + std::to_string((int)(sx / 32)) + "," +
                       std::to_string((int)(sy / 32)) + ") -> (" +
                       std::to_string(endX) + "," + std::to_string(endY) +
                       ") netid=" + std::to_string(nid));
        }
        if (self) {
            float rt = g_currentTime + 0.05f;
            for (auto& t : self->threads)
                if (t.co == L) { t.resumeTime = rt; break; }
        }
        lua_yieldk(L, 0, 0, walk_wait_cont);
        return 0;
    }
    int startX = (int)luaL_checkinteger(L, 1);
    int startY = (int)luaL_checkinteger(L, 2);
    int endX = (int)luaL_checkinteger(L, 3);
    int endY = (int)luaL_checkinteger(L, 4);
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    if (startX == endX && startY == endY) {
        lua_pushinteger(L, startX); lua_rawseti(L, -2, 1);
        lua_pushinteger(L, startY); lua_rawseti(L, -2, 2);
        return 1;
    }
    int idx = 1;
    int dx = (endX > startX) ? 1 : -1;
    int dy = (endY > startY) ? 1 : -1;
    int cx = startX, cy = startY;
    while (cx != endX || cy != endY) {
        if (cx != endX) cx += dx;
        else cy += dy;
        lua_pushinteger(L, cx); lua_rawseti(L, -2, idx++);
        lua_pushinteger(L, cy); lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_PathFind(lua_State* L) {
    return lua_FindPath(L);
}

int LuaExecutor::lua_CheckPath(lua_State* L) {
    int x = (int)luaL_checkinteger(L, 1);
    int y = (int)luaL_checkinteger(L, 2);
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    bool walkable = false;
    if (x >= 0 && x < gs.world_size_x && y >= 0 && y < gs.world_size_y &&
        !gs.tiles.empty() && y < (int)gs.tiles.size() && x < (int)gs.tiles[y].size()) {
        const TileData& t = gs.tiles[y][x];
        bool coll = (t.fg != 0);
        if (t.fg != 0) {
            auto it = gs.itemDatabase.find(t.fg);
            if (it != gs.itemDatabase.end()) coll = (it->second.coltype != 0);
        }
        walkable = !coll;
    }
    lua_pushboolean(L, walkable);
    return 1;
}

int LuaExecutor::lua_IsSolid(lua_State* L) {
    int x = (int)luaL_checkinteger(L, 1);
    int y = (int)luaL_checkinteger(L, 2);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    bool solid = false;
    if (x >= 0 && x < gs.world_size_x && y >= 0 && y < gs.world_size_y &&
        !gs.tiles.empty() && y < (int)gs.tiles.size() && x < (int)gs.tiles[y].size()) {
        solid = (gs.tiles[y][x].fg != 0);
    }
    lua_pushboolean(L, solid);
    return 1;
}

// shared by RunThread(fn, ...) / LoadEncrypt / LoadEncryptedFile:
// moves fn (at fnIndex) + nargs values into a fresh coroutine and resumes it.
void LuaExecutor::startThread(lua_State* L, int fnIndex, int nargs) {
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    lua_State* co = lua_newthread(L);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    // stack: ... fn arg1..argn  → copy them to co
    int base = lua_gettop(L) - nargs;   // fnIndex should equal base
    lua_pushvalue(L, base);             // fn copy
    for (int i = 1; i <= nargs; i++) lua_pushvalue(L, base + i);
    lua_xmove(L, co, nargs + 1);
    // grace period: prevents the render-thread pump from resuming this co
    // concurrently with our initial lua_resume below (resumeTime 0 = eligible)
    if (self) self->threads.push_back({co, g_currentTime + 0.25f, ref});
    int nres;
    int status = lua_resume(co, L, 0, &nres);
    if (status == LUA_OK) {
        if (self) { for (auto it = self->threads.begin(); it != self->threads.end(); ++it) if (it->co == co) { self->threads.erase(it); break; } }
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    } else if (status != LUA_YIELD) {
        const char* errmsg = lua_tostring(co, -1);
        consoleLog("[ERROR] Thread: " + std::string(errmsg ? errmsg : "(non-string error object)"));
        lua_pop(co, 1);
        if (self) { for (auto it = self->threads.begin(); it != self->threads.end(); ++it) if (it->co == co) { self->threads.erase(it); break; } }
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    }
}

int LuaExecutor::lua_RunThread(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int nargs = lua_gettop(L) - 1;
    startThread(L, 1, nargs);
    return 0;
}

int LuaExecutor::lua_Sleep(lua_State* L) {
    int ms = (int)luaL_checkinteger(L, 1);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (self) {
        float resumeTime = g_currentTime + ms / 1000.0f;
        for (auto& t : self->threads) if (t.co == L) { t.resumeTime = resumeTime; break; }
    }
    return lua_yield(L, 0);
}

int LuaExecutor::lua_GetPing(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_pushinteger(L, gs.ping_ms);
    return 1;
}

int LuaExecutor::lua_GetItemCount(lua_State* L) {
    int id = (int)luaL_checkinteger(L, 1);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    int total = 0;
    for (auto& item : gs.inventory) {
        if (item.id == id) total += item.count;
    }
    lua_pushinteger(L, total);
    return 1;
}

int LuaExecutor::lua_GetItemInfo(lua_State* L) {
    // bothax: GetItemInfo(int id) / GetItemInfo(string name)
    itemdb::ensureLoaded();
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    if (lua_type(L, 1) == LUA_TNUMBER) {
        int id = (int)luaL_checkinteger(L, 1);
        auto it = gs.itemDatabase.find(id);
        if (it != gs.itemDatabase.end()) { lua_pop(L, 1); pushItemInfo(L, it->second); return 1; }
    } else {
        const char* name = luaL_checkstring(L, 1);
        for (auto& kv : gs.itemDatabase) {
            if (_stricmp(kv.second.name.c_str(), name) == 0) { lua_pop(L, 1); pushItemInfo(L, kv.second); return 1; }
        }
    }
    ItemInfo unknown;
    unknown.name = "Unknown";
    lua_pop(L, 1);
    pushItemInfo(L, unknown);
    return 1;
}

int LuaExecutor::lua_MessageBox(lua_State* L) {
    const char* text = luaL_checkstring(L, 1);
    const char* caption = lua_isstring(L, 2) ? lua_tostring(L, 2) : "EpsHax";
    MessageBoxA(nullptr, text, caption, MB_OK | MB_TOPMOST);
    return 0;
}

int LuaExecutor::lua_RemoveCallbacks(lua_State* L) {
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    for (auto& cb : self->callbacks) luaL_unref(L, LUA_REGISTRYINDEX, cb.ref);
    self->callbacks.clear();
    rescanTankFlag(self->callbacks);
    return 0;
}

int LuaExecutor::lua_RemoveCallback(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    for (auto it = self->callbacks.begin(); it != self->callbacks.end(); ) {
        if (it->name == name) { luaL_unref(L, LUA_REGISTRYINDEX, it->ref); it = self->callbacks.erase(it); } else { ++it; }
    }
    rescanTankFlag(self->callbacks);
    return 0;
}

int LuaExecutor::lua_EditToggle(lua_State* L) {
    bool enabled = lua_isboolean(L, 1) ? lua_toboolean(L, 1) : true;
    const char* action = enabled ? "action|edit\n" : "action|exit_edit\n";
    scanner::CallSendPacket(4, action);
    debugLog("[EDIT] EditToggle: " + std::string(enabled ? "ON" : "OFF"));
    return 0;
}

int LuaExecutor::lua_GetGhost(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_pushboolean(L, (gs.localPlayer.flags & 8) != 0);
    return 1;
}

int LuaExecutor::lua_GetAccesslist(lua_State* L) {
    lua_newtable(L);
    return 1;
}

int LuaExecutor::lua_GetLocalObject(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    lua_pushnumber(L, gs.localPlayer.pos_x); lua_setfield(L, -2, "pos_x");
    lua_pushnumber(L, gs.localPlayer.pos_y); lua_setfield(L, -2, "pos_y");
    lua_pushinteger(L, gs.localPlayer.tile_x); lua_setfield(L, -2, "tile_x");
    lua_pushinteger(L, gs.localPlayer.tile_y); lua_setfield(L, -2, "tile_y");
    lua_pushstring(L, gs.localPlayer.name.c_str()); lua_setfield(L, -2, "name");
    lua_pushinteger(L, gs.localPlayer.netid); lua_setfield(L, -2, "netid");
    lua_pushinteger(L, gs.localPlayer.userid); lua_setfield(L, -2, "userid");
    return 1;
}

int LuaExecutor::lua_GetDroppedItems(lua_State* L) {
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& obj : gs.objects) {
        if (obj.count > 0) {
            lua_newtable(L);
            lua_pushinteger(L, obj.id); lua_setfield(L, -2, "id");
            lua_pushinteger(L, obj.oid); lua_setfield(L, -2, "oid");
            lua_pushnumber(L, obj.pos_x); lua_setfield(L, -2, "pos_x");
            lua_pushnumber(L, obj.pos_y); lua_setfield(L, -2, "pos_y");
            lua_pushinteger(L, obj.count); lua_setfield(L, -2, "count");
            lua_rawseti(L, -2, idx++);
        }
    }
    return 1;
}

int LuaExecutor::lua_SendWebhook(lua_State* L) {
    const char* webhookUrl = luaL_checkstring(L, 1);
    const char* payload = luaL_checkstring(L, 2);
    std::string urlStr(webhookUrl);
    std::string payStr(payload);
    std::thread([urlStr, payStr]() {
        std::wstring wUrl(urlStr.begin(), urlStr.end());
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszHostName = new wchar_t[256]; urlComp.dwHostNameLength = 256;
        urlComp.lpszUrlPath = new wchar_t[1024]; urlComp.dwUrlPathLength = 1024;
        urlComp.lpszExtraInfo = new wchar_t[256]; urlComp.dwExtraInfoLength = 256;
        if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &urlComp)) {
            delete[] urlComp.lpszHostName; delete[] urlComp.lpszUrlPath; delete[] urlComp.lpszExtraInfo; return;
        }
        std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        path.append(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
        HINTERNET hSession = WinHttpOpen(L"EpsHax/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) { delete[] urlComp.lpszHostName; delete[] urlComp.lpszUrlPath; delete[] urlComp.lpszExtraInfo; return; }
        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComp.nPort, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); delete[] urlComp.lpszHostName; delete[] urlComp.lpszUrlPath; delete[] urlComp.lpszExtraInfo; return; }
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); delete[] urlComp.lpszHostName; delete[] urlComp.lpszUrlPath; delete[] urlComp.lpszExtraInfo; return; }
        BOOL sent = WinHttpSendRequest(hRequest, L"Content-Type: application/json", -1L, (LPVOID)payStr.c_str(), (DWORD)payStr.size(), (DWORD)payStr.size(), 0);
        if (sent) {
            WinHttpReceiveResponse(hRequest, nullptr);
            DWORD statusCode = 0, statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
            debugLog("[WEBHOOK] Response: " + std::to_string((int)statusCode));
        }
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        delete[] urlComp.lpszHostName; delete[] urlComp.lpszUrlPath; delete[] urlComp.lpszExtraInfo;
    }).detach();
    return 0;
}

int LuaExecutor::lua_timer_Create(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    float interval = (float)luaL_checknumber(L, 2);  // seconds (GrowPai semantics)
    int repeat_count = (int)luaL_checkinteger(L, 3);
    luaL_checktype(L, 4, LUA_TFUNCTION);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    lua_pushvalue(L, 4);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    self->timers.push_back({name, interval, repeat_count, ref, g_currentTime});
    debugLog("[TIMER] Create: " + std::string(name));
    return 0;
}

int LuaExecutor::lua_timer_Destroy(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    for (auto it = self->timers.begin(); it != self->timers.end(); ) {
        if (it->name == name) { luaL_unref(L, LUA_REGISTRYINDEX, it->ref); it = self->timers.erase(it); } else { ++it; }
    }
    return 0;
}

int LuaExecutor::lua_timer_Update(lua_State* L) { return 0; }

int LuaExecutor::lua_AddCallback(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    const char* type = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    lua_pushvalue(L, 3);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    self->callbacks.push_back({name, type, ref});
    if (std::string(type) == "OnTankPacket") g_OnTankPacket.store(true);
    debugLog("[CALLBACK] AddCallback: " + std::string(name) + " type=" + std::string(type));
    return 0;
}

// GrowPai GetWorld() -> { name = ... } (world name tracked from spawn /
// world_name varlists / log lines; may briefly lag on world change)
int LuaExecutor::lua_GetWorld(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lock(gs.mtx);
    lua_newtable(L);
    lua_pushstring(L, gs.localPlayer.world.c_str()); lua_setfield(L, -2, "name");
    lua_pushinteger(L, gs.world_size_x); lua_setfield(L, -2, "width");
    lua_pushinteger(L, gs.world_size_y); lua_setfield(L, -2, "height");
    lua_pushinteger(L, gs.world_size_x * gs.world_size_y); lua_setfield(L, -2, "tilecount");
    lua_pushinteger(L, (int)gs.objects.size()); lua_setfield(L, -2, "objectcount");
    int lastoid = 0;
    for (auto& o : gs.objects) if (o.oid > lastoid) lastoid = o.oid;
    lua_pushinteger(L, lastoid); lua_setfield(L, -2, "lastoid");
    return 1;
}

// bothax AddHook(hookName, id(int|string), fn) + GrowPai AddHook(hook, cbName, fn)
// Bothax hooks: OnVariant/OnSendPacket/OnSendPacketRaw dispatch SYNCHRONOUSLY
// from the packet paths (see LuaHooks in lua_bothax.cpp); the rest queue via tick.
int LuaExecutor::lua_AddHook(lua_State* L) {
    const char* hook = luaL_checkstring(L, 1);   // hook name
    const char* name = luaL_checkstring(L, 2);   // id (numbers stringify)
    luaL_checktype(L, 3, LUA_TFUNCTION);
    std::string h = hook, ev;
    if (h == "OnVariant") ev = "OnVariant";
    else if (h == "OnSendPacket") ev = "OnSendPacket";
    else if (h == "OnSendPacketRaw") ev = "OnSendPacketRaw";
    else if (h == "OnProcessTankUpdate") ev = "OnTankPacket";
    else if (h == "OnWorldTouch") ev = "OnWorldTouch";
    else if (h == "OnDraw") ev = "OnDraw";
    else if (h == "OnInput") ev = "OnInput";
    // GrowPai legacy spellings
    else if (h == "onvariant" || h == "onconsolemessage" || h == "onvarlist") ev = "OnVarlist";
    else if (h == "onprocesstankupdatepacket" || h == "ontankpacket") ev = "OnTankPacket";
    else if (h == "onpacket") ev = "OnPacket";
    else ev = h;
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    lua_pushvalue(L, 3);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    self->callbacks.push_back({name, ev, ref});
    if (ev == "OnTankPacket") g_OnTankPacket.store(true);
    debugLog("[CALLBACK] AddHook: " + std::string(name) + " hook=" +
             std::string(hook) + " -> " + ev);
    return 0;
}

// bothax RemoveHook(id) — id matches the string form used at AddHook time
int LuaExecutor::lua_RemoveHook(lua_State* L) {
    const char* id = luaL_checkstring(L, 1);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    for (auto it = self->callbacks.begin(); it != self->callbacks.end(); ) {
        if (it->name == id) { luaL_unref(L, LUA_REGISTRYINDEX, it->ref); it = self->callbacks.erase(it); }
        else ++it;
    }
    rescanTankFlag(self->callbacks);
    debugLog("[CALLBACK] RemoveHook: " + std::string(id));
    return 0;
}

// bothax RemoveHooks() — drop every registered event listener
int LuaExecutor::lua_RemoveHooks(lua_State* L) {
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    for (auto& cb : self->callbacks) luaL_unref(L, LUA_REGISTRYINDEX, cb.ref);
    self->callbacks.clear();
    rescanTankFlag(self->callbacks);
    debugLog("[CALLBACK] RemoveHooks: all hooks removed");
    return 0;
}

// GrowPai MakeRequest(url, method, headers, body) — Discord webhook POST
// only (the sole use in real scripts); other methods are logged and skipped.
int LuaExecutor::lua_MakeRequest(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    const char* method = luaL_optstring(L, 2, "POST");
    if (lua_gettop(L) < 4 || !lua_isstring(L, 4)) return 0;
    if (std::string(method) != "POST" && std::string(method) != "post") {
        debugLog("[LUA] MakeRequest: method " + std::string(method) + " ignored");
        return 0;
    }
    const char* body = lua_tostring(L, 4);
    if (!url || !*url || !body) return 0;
    lua_remove(L, 3); // drop headers table -> (url, method, body)
    lua_remove(L, 2); // drop method        -> (url, body)
    return lua_SendWebhook(L);
}

int LuaExecutor::lua_RegisterCommand(lua_State* L) {
    const char* cmd = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA) self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!self) return 0;
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    self->commands[cmd] = ref;
    g_luaCommands.insert(cmd);
    debugLog("[CALLBACK] RegisterCommand: /" + std::string(cmd));
    return 0;
}

void LuaExecutor::registerAPI() {
    lua_register(L, "SendPacket", lua_SendPacket);
    lua_register(L, "SendPacketRaw", lua_SendPacketRaw);
    lua_register(L, "SendPacketRawClient", lua_SendPacketRaw);
    lua_register(L, "SendVarlist", lua_SendVarlist);
    lua_register(L, "log", lua_log);
    lua_register(L, "FindPath", lua_FindPath);
    lua_register(L, "PathFind", lua_PathFind);
    lua_register(L, "CheckPath", lua_CheckPath);
    lua_register(L, "IsSolid", lua_IsSolid);
    lua_register(L, "GetLocal", lua_GetLocal);
    lua_register(L, "GetInventory", lua_GetInventory);
    lua_register(L, "GetPlayers", lua_GetPlayers);
    lua_register(L, "GetObjects", lua_GetObjects);
    lua_register(L, "GetTile", lua_GetTile);
    lua_register(L, "GetTiles", lua_GetTiles);
    lua_register(L, "RunThread", lua_RunThread);
    lua_register(L, "Sleep", lua_Sleep);
    lua_register(L, "GetPing", lua_GetPing);
    lua_register(L, "GetItemCount", lua_GetItemCount);
    lua_register(L, "GetItemInfo", lua_GetItemInfo);
    lua_register(L, "MessageBox", lua_MessageBox);
    lua_register(L, "RemoveCallbacks", lua_RemoveCallbacks);
    lua_register(L, "RemoveCallback", lua_RemoveCallback);
    lua_register(L, "EditToggle", lua_EditToggle);
    lua_register(L, "SendWebhook", lua_SendWebhook);
    lua_register(L, "AddCallback", lua_AddCallback);
    lua_register(L, "RegisterCommand", lua_RegisterCommand);
    lua_register(L, "GetGhost", lua_GetGhost);
    lua_register(L, "GetAccesslist", lua_GetAccesslist);
    lua_register(L, "GetLocalObject", lua_GetLocalObject);
    lua_register(L, "GetDroppedItems", lua_GetDroppedItems);
    // GrowPai-compat aliases
    lua_register(L, "GetWorld", lua_GetWorld);
    lua_register(L, "AddHook", lua_AddHook);
    lua_register(L, "MakeRequest", lua_MakeRequestBx);
    lua_register(L, "SendVariantList", lua_SendVariantListBx);
    lua_register(L, "LogToConsole", lua_log);
    // ── bothax API ───────────────────────────────────────────────────
    lua_register(L, "ChangeValue", lua_ChangeValue);
    lua_register(L, "Encrypt", lua_Encrypt);
    lua_register(L, "EncryptFile", lua_EncryptFile);
    lua_register(L, "LoadEncrypt", lua_LoadEncrypt);
    lua_register(L, "LoadEncryptedFile", lua_LoadEncryptedFile);
    lua_register(L, "GetCamera", lua_GetCamera);
    lua_register(L, "GetClient", lua_GetClient);
    lua_register(L, "GetItemByIDSafe", lua_GetItemByIDSafe);
    lua_register(L, "GetItemByName", lua_GetItemByName);
    lua_register(L, "GetItemInfoList", lua_GetItemInfoList);
    lua_register(L, "GetItemsByPartialName", lua_GetItemsByPartialName);
    lua_register(L, "GetNPC", lua_GetNPC);
    lua_register(L, "GetNPCList", lua_GetNPCList);
    lua_register(L, "GetObjectList", lua_GetObjectList);
    lua_register(L, "GetPlayer", lua_GetPlayer);
    lua_register(L, "GetPlayerInfo", lua_GetPlayerInfo);
    lua_register(L, "GetPlayerItems", lua_GetPlayerItems);
    lua_register(L, "GetPlayerList", lua_GetPlayerList);
    lua_register(L, "Hash32", lua_Hash32);
    lua_register(L, "Hash64", lua_Hash64);
    lua_register(L, "RemoveHook", lua_RemoveHook);
    lua_register(L, "RemoveHooks", lua_RemoveHooks);
    lua_register(L, "RequestJoinWorld", lua_RequestJoinWorld);
    lua_register(L, "RunDelayed", lua_RunDelayed);
    lua_register(L, "SetItemSelected", lua_SetItemSelected);
    lua_register(L, "SetTileFlags", lua_SetTileFlags);
    lua_newtable(L);
    lua_pushcfunction(L, lua_timer_Create);
    lua_setfield(L, -2, "Create");
    lua_pushcfunction(L, lua_timer_Destroy);
    lua_setfield(L, -2, "Destroy");
    lua_pushcfunction(L, lua_timer_Update);
    lua_setfield(L, -2, "Update");
    lua_setglobal(L, "timer");
}
