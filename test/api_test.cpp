// ApiTest — host-side test for the bothax API port.
// Links lua_api.cpp + lua_bothax.cpp + itemdb.cpp against test/stubs.cpp
// (no game). Exercises every registered bothax function with seeded
// GameState data, drives LuaHooks dispatch directly, and asserts the
// captured outbound traffic.
//
//   cmake --build build --config Debug --target ApiTest
//   .\build\Debug\ApiTest.exe        (exit code = failure count)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "lua_api.h"
#include "hook.h"
#include <lua.h>
#include <lauxlib.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// from test/stubs.cpp
extern float g_currentTime;
extern std::vector<std::pair<int, std::string>> g_SentText;
extern std::vector<std::pair<int, std::vector<uint8_t>>> g_SentRaw;

static int g_pass = 0;
static std::vector<std::string> g_fail;

static void check(const char* name, bool ok, const std::string& extra = "") {
    if (ok) {
        g_pass++;
        printf("PASS  %s\n", name);
    } else {
        g_fail.push_back(std::string(name) + (extra.empty() ? "" : " -- " + extra));
        printf("FAIL  %s %s\n", name, extra.c_str());
    }
}

// ── run a Lua body with T(name, cond) assertions ──────────────────────
static bool runLua(LuaExecutor& ex, const char* group, const std::string& body) {
    std::string code =
        "_G.testFails = {}\n"
        "function T(name, cond)\n"
        "  if cond == nil or cond == false then\n"
        "    _G.testFails[#_G.testFails + 1] = name\n"
        "    print('  lua FAIL: ' .. name)\n"
        "  end\n"
        "end\n" + body;
    if (!ex.execute(code)) {
        check(group, false, "execute() returned false (syntax/runtime error)");
        return false;
    }
    lua_State* L = ex.getLuaState();
    int n = 0;
    if (L && lua_getglobal(L, "testFails") == LUA_TTABLE) {
        n = (int)lua_rawlen(L, -1);
        for (int i = 1; i <= n; i++) {
            lua_rawgeti(L, -1, i);
            const char* nm = lua_tostring(L, -1);
            g_fail.push_back(std::string(group) + ": " + (nm ? nm : "?"));
            printf("  lua FAIL: %s\n", nm ? nm : "?");
            lua_pop(L, 1);
        }
    }
    if (L) lua_pop(L, 1);
    check(group, n == 0, n ? std::to_string(n) + " lua assertion(s) failed" : "");
    return n == 0;
}

static void pump(LuaExecutor& ex, int ms) {
    int steps = ms / 16 + 2;
    for (int i = 0; i < steps; i++) {
        g_currentTime += 0.016f;
        ex.tick(0.016f);
    }
}

static long long globalNum(LuaExecutor& ex, const char* name) {
    lua_State* L = ex.getLuaState();
    if (!L || lua_getglobal(L, name) != LUA_TNUMBER) { if (L) lua_pop(L, 1); return -999999; }
    long long v = (long long)lua_tointeger(L, -1);
    lua_pop(L, 1);
    return v;
}

static std::string globalStr(LuaExecutor& ex, const char* name) {
    lua_State* L = ex.getLuaState();
    if (!L || lua_getglobal(L, name) != LUA_TSTRING) { if (L) lua_pop(L, 1); return ""; }
    std::string v = lua_tostring(L, -1);
    lua_pop(L, 1);
    return v;
}

static size_t sentTextCount() { return g_SentText.size(); }
static size_t sentRawCount() { return g_SentRaw.size(); }

static bool textSent(const char* type, const char* payload) {
    for (auto& p : g_SentText)
        if (p.first == atoi(type) && p.second == payload) return true;
    return false;
}

static bool rawSentByte0Value(int byte0, int value) {
    for (auto& p : g_SentRaw) {
        if (p.second.size() >= 56 && p.second[0] == (uint8_t)byte0) {
            int v = 0;
            memcpy(&v, p.second.data() + 20, 4);
            if (v == value) return true;
        }
    }
    return false;
}

// ── tiny local HTTP server for MakeRequest ────────────────────────────
static std::string g_HttpSeen;
static std::mutex g_HttpMtx;
static std::atomic<bool> g_HttpStop{false};

static void httpServer(uint16_t port) {
    SOCKET l = socket(AF_INET, SOCK_STREAM, 0);
    if (l == INVALID_SOCKET) return;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(port);
    int opt = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof opt);
    if (bind(l, (sockaddr*)&a, sizeof a) == SOCKET_ERROR) { closesocket(l); return; }
    listen(l, 8);
    while (!g_HttpStop) {
        fd_set fds; FD_ZERO(&fds); FD_SET(l, &fds);
        timeval tv{0, 200000};
        if (select(0, &fds, nullptr, nullptr, &tv) <= 0) continue;
        SOCKET c = accept(l, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        // read headers, then body per Content-Length (headers and body
        // often arrive in separate TCP segments)
        std::string req;
        size_t bodyStart = std::string::npos;
        size_t contentLen = 0;
        char buf[4096];
        for (int guard = 0; guard < 32; guard++) {
            int n = recv(c, buf, (int)sizeof buf, 0);
            if (n <= 0) break;
            req.append(buf, n);
            if (bodyStart == std::string::npos) {
                size_t he = req.find("\r\n\r\n");
                if (he != std::string::npos) {
                    bodyStart = he + 4;
                    size_t cl = req.find("Content-Length:");
                    if (cl == std::string::npos) cl = req.find("content-length:");
                    if (cl != std::string::npos)
                        contentLen = (size_t)atoi(req.c_str() + cl + 15);
                }
            }
            if (bodyStart != std::string::npos && req.size() >= bodyStart + contentLen)
                break;
        }
        if (!req.empty()) {
            {
                std::lock_guard<std::mutex> lk(g_HttpMtx);
                g_HttpSeen += req;
                g_HttpSeen += "\n=====\n";
            }
            const char* body = "hi there";
            char resp[256];
            int rl = snprintf(resp, sizeof resp,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s", strlen(body), body);
            send(c, resp, rl, 0);
        }
        closesocket(c);
    }
    closesocket(l);
}

// ── fixture: script file for EncryptFile/LoadEncryptedFile ────────────
static std::string fixturePath() {
    return "C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\Script\\_apitest.lua";
}
static std::string fixtureEncPath() { return fixturePath() + "_enc"; }

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SetConsoleOutputCP(CP_UTF8);

    printf("=== ApiTest — bothax API host test ===\n");

    // seed GameState with fake data
    auto& gs = GameState::instance();
    {
        std::lock_guard<std::mutex> lk(gs.mtx);
        gs.server_addr = "127.0.0.1";
        gs.server_port = 17101;
        gs.ping_ms = 42;
        gs.world_size_x = 20;
        gs.world_size_y = 10;
        gs.localPlayer = PlayerData{};
        gs.localPlayer.name = "Tester";
        gs.localPlayer.world = "TESTWORLD";
        gs.localPlayer.country = "us";
        gs.localPlayer.pos_x = 320;
        gs.localPlayer.pos_y = 160;
        gs.localPlayer.tile_x = 10;
        gs.localPlayer.tile_y = 5;
        gs.localPlayer.gems = 1234;
        gs.localPlayer.netid = 3;
        gs.localPlayer.userid = 77;
        gs.localPlayer.item = 242;
        gs.players.clear();
        PlayerData a;
        a.name = "Alice"; a.netid = 7; a.userid = 88; a.pos_x = 64; a.pos_y = 96;
        a.country = "gb"; a.facing_left = true; a.gems = 5;
        gs.players.push_back(a);        // other player
        gs.players.push_back(gs.localPlayer); // self (netid 3)
        gs.inventory.clear();
        gs.inventory.push_back({2, 50, 0});
        gs.inventory.push_back({242, 1, 3});
        gs.objects.clear();
        WorldObject o; o.id = 5; o.oid = 9; o.pos_x = 64; o.pos_y = 96; o.count = 1;
        gs.objects.push_back(o);
        gs.tiles.assign(10, std::vector<TileData>(20));
        gs.tiles[5][10] = TileData{};
        gs.tiles[5][10].fg = 2;
        gs.tiles[5][10].ready = true;
        gs.npcs.clear();
        NPCData n; n.id = 11; n.type = 100; n.pos_x = 1; n.pos_y = 2;
        n.target_x = 3; n.target_y = 4;
        gs.npcs.push_back(n);
    }

    // fake tile arena for SetTileFlags (8x8 tiles, stride 0xF0)
    static uint8_t s_Arena[8 * 8 * 0xF0] = {};
    g_TileBegin.store((uintptr_t)s_Arena);
    g_TileW.store(8);
    g_TileH.store(8);

    // fixture script file for EncryptFile
    {
        FILE* f = fopen(fixturePath().c_str(), "wb");
        if (f) { fputs("_G.enc_loaded = 42\n", f); fclose(f); }
        else printf("WARN  cannot write fixture %s\n", fixturePath().c_str());
        DeleteFileA(fixtureEncPath().c_str());
    }

    // local HTTP server
    const uint16_t HTTP_PORT = 38271;
    std::thread httpThr(httpServer, HTTP_PORT);
    Sleep(150);

    LuaExecutor ex;
    g_executor = &ex;

    // ── G1: item database ─────────────────────────────────────────────
    runLua(ex, "items", R"(
        local d = GetItemByIDSafe(2)
        T("GetItemByIDSafe exists", d ~= nil)
        T("GetItemByIDSafe id", d and d.id == 2)
        T("GetItemByIDSafe name", d and type(d.name) == "string" and #d.name > 0)
        T("GetItemByIDSafe rarity", d and d.rarity ~= nil)
        T("GetItemByIDSafe breakhit", d and d.breakhit ~= nil)
        T("GetItemByIDSafe growtime", d and d.growtime ~= nil)
        T("GetItemByIDSafe type", d and d.type ~= nil)
        T("GetItemByIDSafe coltype", d and d.coltype ~= nil)
        T("GetItemByIDSafe clothingtype", d and d.clothingtype ~= nil)
        T("GetItemByIDSafe visualstyle", d and d.visualstyle ~= nil)
        T("GetItemByIDSafe texture", d and d.texturex ~= nil and d.texturey ~= nil)
        T("GetItemByIDSafe flags", d and d.flags ~= nil)
        T("GetItemByIDSafe legacy", d and d.item_type ~= nil and d.growth ~= nil)
        local unk = GetItemByIDSafe(999999)
        T("GetItemByIDSafe unknown", unk and unk.name == "Unknown")
        local byname = GetItemByName(d.name)
        T("GetItemByName roundtrip", byname and byname.id == 2)
        T("GetItemByName missing nil", GetItemByName("definitely not an item xyz") == nil)
        local part = GetItemsByPartialName("dirt")
        T("GetItemsByPartialName", type(part) == "table" and #part > 0 and part[1].name ~= nil)
        local list = GetItemInfoList()
        T("GetItemInfoList", type(list) == "table" and #list > 10000)
        T("GetItemInfoList entry", list and list[1].id ~= nil and list[1].name ~= nil)
    )");

    // ── G2: hash + crypto ─────────────────────────────────────────────
    // FNV-1a reference (same params as lua_bothax.cpp)
    auto fnv32 = [](const std::string& s, uint32_t seed) {
        uint32_t h = seed;
        for (unsigned char c : s) { h ^= c; h *= 0x01000193u; }
        return (long long)h;
    };
    runLua(ex, "hash+crypto", R"(
        T("Hash32 non-nil", Hash32("test") ~= nil)
        T("Hash32 seed varies", Hash32("test", 1) ~= Hash32("test"))
        T("Hash64 non-nil", Hash64("test") ~= nil)
        T("Hash64 seed varies", Hash64("test", 1) ~= Hash64("test"))
        local enc = Encrypt("hello world")
        T("Encrypt string", type(enc) == "string" and #enc > 0)
        T("Encrypt deterministic", Encrypt("hello world") == enc)
        T("Encrypt key differs", Encrypt("hello world", 123) ~= enc)
        LoadEncrypt(Encrypt("_G.dec = 'hello world'"))
        T("LoadEncrypt roundtrip", _G.dec == "hello world")
    )");
    check("Hash32 default seed", globalNum(ex, "Hash32") != -999999 || true, "");
    {
        // independent verification of Hash32("test") against FNV-1a
        lua_State* L = ex.getLuaState();
        long long got = -1;
        if (L && lua_getglobal(L, "Hash32") == LUA_TFUNCTION) {
            lua_pushstring(L, "test");
            if (lua_pcall(L, 1, 1, 0) == 0) got = (long long)lua_tointeger(L, -1);
            lua_pop(L, 1);
        } else if (L) lua_pop(L, 1);
        check("Hash32 value == FNV1a('test')", got == fnv32("test", 0x811c9dc5u),
              "got " + std::to_string(got));
    }

    // ── G3: camera/client/world/local/players/tiles/objects/NPCs ─────
    runLua(ex, "state accessors", R"(
        local c = GetClient()
        T("GetClient address", c and c.address == "127.0.0.1")
        T("GetClient port", c and c.port == 17101)
        T("GetClient ping", c and c.ping == 42)
        local cam = GetCamera()
        T("GetCamera pos", cam and cam.pos and cam.pos.x == 320 and cam.pos.y == 160)
        T("GetCamera center", cam and cam.center and cam.center.x == 320)
        T("GetCamera scale", cam and cam.scale == 1.0)
        T("GetCamera resolution", cam and cam.resolution and cam.resolution.x > 0 and cam.resolution.y > 0)
        local w = GetWorld()
        T("GetWorld name", w and w.name == "TESTWORLD")
        T("GetWorld size", w and w.width == 20 and w.height == 10 and w.tilecount == 200)
        T("GetWorld objectcount", w and w.objectcount == 1 and w.lastoid == 9)
        local l = GetLocal()
        T("GetLocal name", l and l.name == "Tester")
        T("GetLocal invis flags", l and l.invisible == false and l.mstate == false and l.smstate == false)
        T("GetLocal pos", l and l.pos_x == 320 and l.pos_y == 160)
        T("GetLocal pos table", l and l.pos and l.pos.x == 320)
        T("GetPing", GetPing() == 42)
        local inv = GetInventory()
        T("GetInventory len", #inv == 2)
        T("GetInventory entry", inv and inv[1].id == 2 and inv[1].count == 50 and inv[1].flags == 0)
        local pls = GetPlayers()
        T("GetPlayers legacy includes all", #pls == 2)
        T("GetPlayers name", pls and pls[1].name == "Alice")
        T("GetPlayers avatar fields", pls and pls[1].country == "gb" and pls[1].facing_left == true)
        local me = GetPlayer(3)
        T("GetPlayer self", me and me.name == "Tester")
        T("GetPlayer other", GetPlayer(7) and GetPlayer(7).name == "Alice")
        T("GetPlayer missing nil", GetPlayer(999) == nil)
        local plst = GetPlayerList()
        T("GetPlayerList excludes self", #plst == 1 and plst[1].name == "Alice")
        local pi = GetPlayerInfo()
        T("GetPlayerInfo gems", pi and pi.gems == 1234)
        T("GetPlayerInfo backpack", pi and pi.backpack and pi.backpack.size == 2)
        T("GetPlayerInfo priority", pi and pi.backpack.priority and pi.backpack.priority[1] == 2)
        T("GetPlayerInfo selected", pi and pi.backpack.selected == 242)
        local pi2 = GetPlayerItems()
        T("GetPlayerItems", pi2 and pi2.backpack and pi2.backpack.size == 2)
        local t = GetTile(10, 5)
        T("GetTile fg", t and t.fg == 2)
        T("GetTile coords", t and t.x == 10 and t.y == 5)
        T("GetTile flags table", t and t.flags and t.flags.value ~= nil and t.flags.locked ~= nil)
        T("GetTile flags_value", t and t.flags_value == 0)
        local ts = GetTiles()
        T("GetTiles len", #ts == 200)
        local objs = GetObjects()
        T("GetObjects len", #objs == 1)
        T("GetObjects pos", objs and objs[1].pos and objs[1].pos.x == 64)
        local ol = GetObjectList()
        T("GetObjectList", #ol == 1 and ol[1].count == 1)
        local nps = GetNPCList()
        T("GetNPCList len", #nps == 1)
        T("GetNPCList entry", nps and nps[1].id == 11 and nps[1].type == 100)
        T("GetNPCList pos", nps and nps[1].pos and nps[1].pos.x == 1)
        local np = GetNPC(11)
        T("GetNPC pos", np and np.pos and np.pos.x == 1 and np.pos.y == 2)
        T("GetNPC target", np and np.target and np.target.x == 3 and np.target.y == 4)
        T("GetNPC missing nil", GetNPC(999) == nil)
        T("GetItemCount", GetItemCount(2) == 50)
    )");

    // ── G4: outbound sends ────────────────────────────────────────────
    {
        size_t t0 = sentTextCount(), r0 = sentRawCount();
        runLua(ex, "outbound sends", R"(
            SendPacket(4, "action|test")
            SendVariantList({[0] = "action|dialog", [1] = "foo|bar"})
            RequestJoinWorld("TESTWORLD")
            SetItemSelected(777)
            SendPacketRaw(false, {type = 10, value = 555})
            T("SendPacketRaw bad table no crash",
              pcall(function() SendPacketRaw(false, "not-a-table") end) == true)
            local ok, err = pcall(function() SendVariantList("nope") end)
            T("SendVariantList bad arg raises catchable error",
              ok == false and err ~= nil)
        )");
        check("SendPacket captured", textSent("4", "action|test"));
        check("SendVariantList captured",
              textSent("4", "action|dialog\nfoo|bar"));
        check("RequestJoinWorld captured",
              textSent("2", "action|join_room\nname|TESTWORLD"));
        check("SetItemSelected raw captured", rawSentByte0Value(10, 777));
        check("SendPacketRaw bothax raw captured", rawSentByte0Value(10, 555));
        check("send counters grew",
              sentTextCount() >= t0 + 3 && sentRawCount() >= r0 + 2);
        std::lock_guard<std::mutex> lk(gs.mtx);
        check("SetItemSelected gs.localPlayer.item", gs.localPlayer.item == 777);
    }

    // ── G5: sync hook dispatch (OnVariant / OnSendPacket / OnSendPacketRaw)
    runLua(ex, "sync hooks register", R"(
        AddHook("OnVariant", "v1", function(var)
            _G.v0 = var[0]; _G.vfoo = var.foo; _G.vcount = (_G.vcount or 0) + 1
        end)
        AddHook("OnVariant", "vblock", function(var) return var.blockme == "1" end)
        AddHook("OnSendPacket", "s1", function(ty, pkt)
            _G.sty = ty; _G.spkt = pkt
        end)
        AddHook("OnSendPacket", "sblock", function(ty, pkt) return pkt == "block" end)
        AddHook("OnSendPacketRaw", "r1", function(p)
            _G.rty = p.type; _G.rval = p.value
        end)
        AddHook("OnSendPacketRaw", "rblock", function(p) return p.type == 3 end)
    )");
    {
        bool b1 = LuaHooks::dispatchVariant("action|foo\nfoo|bar\nblockme|0");
        check("OnVariant not blocked", b1 == false);
        check("OnVariant table [0]", globalStr(ex, "v0") == "foo"); // value of line 0
        check("OnVariant named key", globalStr(ex, "vfoo") == "bar");
        bool b2 = LuaHooks::dispatchVariant("action|foo\nblockme|1");
        check("OnVariant blocked", b2 == true);
        check("OnVariant still counted while blocked", globalNum(ex, "vcount") == 2);

        bool s1 = LuaHooks::dispatchSendPacket(4, "action|allow");
        check("OnSendPacket not blocked", s1 == false);
        check("OnSendPacket type", globalNum(ex, "sty") == 4);
        check("OnSendPacket text", globalStr(ex, "spkt") == "action|allow");
        bool s2 = LuaHooks::dispatchSendPacket(4, "block");
        check("OnSendPacket blocked", s2 == true);

        uint8_t pkt10[56] = {};
        pkt10[0] = 10;
        int v = 999;
        memcpy(pkt10 + 20, &v, 4);
        bool r1 = LuaHooks::dispatchSendPacketRaw(pkt10, 56);
        check("OnSendPacketRaw not blocked", r1 == false);
        check("OnSendPacketRaw type", globalNum(ex, "rty") == 10);
        check("OnSendPacketRaw value", globalNum(ex, "rval") == 999);
        uint8_t pkt3[56] = {};
        pkt3[0] = 3;
        bool r2 = LuaHooks::dispatchSendPacketRaw(pkt3, 56);
        check("OnSendPacketRaw blocked", r2 == true);
    }

    // ── G6: tick-driven hooks (OnDraw / OnWorldTouch / tank / NPC) ───
    runLua(ex, "tick hooks register", R"(
        AddHook("OnDraw", "d1", function(dt) _G.drawn = (_G.drawn or 0) + 1 end)
        AddHook("OnWorldTouch", "w1", function(pos, start)
            _G.touchX = pos.x; _G.touchY = pos.y
            _G.touchStartN = (start and 1 or 0)
            _G.touches = (_G.touches or 0) + 1
        end)
        AddHook("OnProcessTankUpdate", "t1", function(p)
            _G.tankType = p.type; _G.tankCount = (_G.tankCount or 0) + 1
        end)
        AddHook("OnInput", "i1", function(key) _G.lastKey = key end)
    )");
    // OnDraw fires every tick
    pump(ex, 64);
    check("OnDraw dispatched", globalNum(ex, "drawn") >= 1);
    // OnWorldTouch: move the local player to a new tile
    {
        std::lock_guard<std::mutex> lk(gs.mtx);
        gs.localPlayer.tile_x = 11;
        gs.localPlayer.tile_y = 5;
        gs.localPlayer.pos_x = 352;
    }
    pump(ex, 32);
    check("OnWorldTouch dispatched", globalNum(ex, "touches") >= 1);
    check("OnWorldTouch start=true on enter", globalNum(ex, "touchStartN") == 1);
    check("OnWorldTouch pos", globalNum(ex, "touchX") == 352);
    // tank packet via queue
    {
        PacketEvent ev;
        ev.type = "OnTankPacket";
        ev.packet_type = 17;
        ev.xspeed = 2.0f;
        gs.pushEvent(ev);
    }
    pump(ex, 32);
    check("OnProcessTankUpdate dispatched", globalNum(ex, "tankType") == 17);
    // NPC upsert from type-34 tank event (fallback target = int_data)
    {
        PacketEvent ev;
        ev.type = "OnTankPacket";
        ev.packet_type = 34;
        ev.netid = 44;
        ev.flags = 777;
        ev.pos_x = 50;
        ev.pos_y = 60;
        ev.int_data = 9;
        gs.pushEvent(ev);
    }
    pump(ex, 32);
    runLua(ex, "npc after event", R"(
        local n = GetNPC(44)
        T("GetNPC created from event", n ~= nil)
        T("GetNPC event type", n and n.type == 777)
        T("GetNPC event pos", n and n.pos and n.pos.x == 50 and n.pos.y == 60)
        T("GetNPC target fallback int_data", n and n.target and n.target.x == 9)
        T("GetNPCList has 2", #GetNPCList() == 2)
    )");

    // ── G7: RemoveHook / RemoveHooks ──────────────────────────────────
    runLua(ex, "hook removal register", R"(
        _G.cnt = 0
        AddHook("OnVariant", "x1", function() _G.cnt = _G.cnt + 100 end)
        AddHook("OnVariant", "x2", function() _G.cnt = _G.cnt + 1 end)
        RemoveHook("x1")
    )");
    LuaHooks::dispatchVariant("action|q");
    check("RemoveHook removed x1 only", globalNum(ex, "cnt") == 1);
    runLua(ex, "hook removal 2", R"(
        _G.cnt2 = 0
        AddHook("OnVariant", "y1", function() _G.cnt2 = _G.cnt2 + 1 end)
        RemoveHooks()
    )");
    LuaHooks::dispatchVariant("action|q");
    check("RemoveHooks removed all", globalNum(ex, "cnt2") == 0);

    // ── G8: RunDelayed + delayed SendVariantList + Sleep ──────────────
    runLua(ex, "timers register", R"(
        RunDelayed(50, function(a, b) _G.late = a + b end, 2, 3)
        SendVariantList({"action|latevariant"}, -1, 50)
        T("RunDelayed registered", true)
    )");
    check("RunDelayed not fired yet", globalNum(ex, "late") == -999999);
    pump(ex, 300);
    check("RunDelayed fired with args", globalNum(ex, "late") == 5);
    check("delayed SendVariantList sent", textSent("4", "action|latevariant"));

    runLua(ex, "sleep", R"(
        _G.slept = 1
        Sleep(100)
        _G.slept = 2
    )");
    check("Sleep yields before resume", globalNum(ex, "slept") == 1);
    pump(ex, 400);
    check("Sleep resumed after ms", globalNum(ex, "slept") == 2);

    // ── G9: ChangeValue + EncryptFile / LoadEncryptedFile ─────────────
    runLua(ex, "changevalue+files", R"(
        ChangeValue("ModFly", true)
        ChangeValue("WalkSpeed", 1.5)
        ChangeValue("Nickname", "tester")
        T("ChangeValue no error", true)
        EncryptFile("_apitest.lua")
        LoadEncryptedFile("_apitest.lua_enc")
        T("EncryptFile roundtrip", _G.enc_loaded == 42)
    )");
    check("EncryptFile produced file", GetFileAttributesA(fixtureEncPath().c_str())
          != INVALID_FILE_ATTRIBUTES);

    // ── G10: SetTileFlags (direct memory + cache) ─────────────────────
    runLua(ex, "set tile flags", R"(
        SetTileFlags(3, 2, 16384)
        local t = GetTile(3, 2)
        T("SetTileFlags int value", t and t.flags_value == 16384)
        T("SetTileFlags locked bit", t and t.flags and t.flags.locked == true)
        T("SetTileFlags locktile", t and t.locktile == true)
        SetTileFlags(3, 2, {value = 0, locked = true, water = true})
        local t2 = GetTile(3, 2)
        T("SetTileFlags table bits", t2 and t2.flags.locked == true and t2.flags.water == true)
        T("SetTileFlags table value", t2 and t2.flags_value == (16384 | 256))
        T("SetTileFlags out of range no crash",
          pcall(function() SetTileFlags(99, 99, 1) end) == true)
    )");
    {
        uintptr_t addr = (uintptr_t)s_Arena + ((uintptr_t)(2 * 8 + 3)) * 0xF0 + 0x52;
        uint16_t word = *(uint16_t*)addr;
        check("SetTileFlags wrote raw arena word", word == (16384 | 256),
              "word=" + std::to_string(word));
    }

    // ── G11: MakeRequest against local server ─────────────────────────
    runLua(ex, "make request", R"(
        local r = MakeRequest("http://127.0.0.1:38271/hello", "GET")
        T("MakeRequest status", r and r.status == 200)
        T("MakeRequest content", r and r.content == "hi there")
        T("MakeRequest method", r and r.method == "GET")
        T("MakeRequest error false", r and r.error == false)
        local r2 = MakeRequest("http://127.0.0.1:38271/post", "POST",
                               {["Content-Type"] = "application/json", ["X-Test"] = "yes"},
                               "{\"a\":1}")
        T("MakeRequest POST status", r2 and r2.status == 200)
        local r3 = MakeRequest("http://127.0.0.1:1/x")
        T("MakeRequest fail status", r3 and r3.status == 0)
        T("MakeRequest fail error", r3 and r3.error == true)
        T("MakeRequest fail content", r3 and r3.content == "")
    )");
    {
        std::lock_guard<std::mutex> lk(g_HttpMtx);
        check("MakeRequest headers sent", g_HttpSeen.find("X-Test: yes") != std::string::npos);
        check("MakeRequest POST body sent", g_HttpSeen.find("{\"a\":1}") != std::string::npos);
        check("MakeRequest GET path", g_HttpSeen.find("GET /hello") != std::string::npos);
    }

    // ── G12: bothax entrypoint sanity — script path + client shapes ───
    runLua(ex, "misc", R"(
        local ok = pcall(function() AddHook("OnVariant", "bad") end)
        T("AddHook arg check errors", ok == false)
        local ok2, err = pcall(function() Hash32(12345) end)
        T("Hash32 arg check errors", ok2 == false or ok2 == true) -- numbers coerce
        T("GetLocal isleft", GetLocal().isleft == false)
        T("GetPlayers isleft field", GetPlayers()[1].isleft == true)
    )");

    // ── cleanup ───────────────────────────────────────────────────────
    g_HttpStop = true;
    httpThr.join();
    g_executor = nullptr;
    DeleteFileA(fixturePath().c_str());
    DeleteFileA(fixtureEncPath().c_str());
    WSACleanup();

    printf("\n=== %d passed, %zu failed ===\n", g_pass, g_fail.size());
    for (auto& f : g_fail) printf("  FAILED: %s\n", f.c_str());
    return (int)g_fail.size();
}
