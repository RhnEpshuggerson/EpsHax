// bothax Lua API (https://github.com/bothax/bothax README spec).
// Registered in LuaExecutor::registerAPI (lua_api.cpp). The three sync
// hooks OnVariant/OnSendPacket/OnSendPacketRaw are dispatched from the
// packet paths (hook.cpp) through the LuaHooks bridge at the bottom.
//
// Documented approximations (also asserted by test/api_test.cpp):
//  - GetCamera: pos/center = local player pos, scale = 1.0, resolution =
//    game client rect (no camera offset tracked in GameState).
//  - Encrypt/LoadEncrypt: EpsHax XOR+base64 roundtrip scheme — not
//    byte-compatible with bothax' closed-source cipher.
//  - OnVariant "blocking" suppresses EpsHax-side processing only; the
//    recv path cannot withhold bytes from the game.
//  - ChangeValue stores the setting; EpsHax has no matching features to
//    apply it to yet (no error per spec: no return value).
//  - TileFlags named bits follow the mapping in pushTileFlags; raw
//    `value`/`flags_value` are the exact u16 word.

#include "lua_api.h"
#include "hook.h"
#include "scanner.h"
#include "itemdb.h"
#include <lua.h>
#include <lauxlib.h>
#include <windows.h>
#include <winhttp.h>
#include <map>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <functional>

// bothax TileFlags bit layout (u16 tile flag word read/written at +0x52)
enum : unsigned {
    TF_SPLICED  = 0x0001,
    TF_DROPSEED = 0x0002,
    TF_TREE     = 0x0004,
    TF_FLIPPED  = 0x0008,
    TF_ENABLED  = 0x0010,
    TF_PUBLIC   = 0x0080,
    TF_WATER    = 0x0100,
    TF_GLUE     = 0x0200,
    TF_BURN     = 0x0400,
    TF_RED      = 0x0800,
    TF_GREEN    = 0x1000,
    TF_BLUE     = 0x2000,
    TF_LOCKED   = 0x4000,
    TF_SILENCED = 0x8000,
};

namespace {

// ChangeValue store — POD copy (no lua refs, survives state restarts)
struct CVValue {
    int t = 0; // 0=bool 1=number 2=string
    bool b = false;
    double n = 0;
    std::string s;
};
std::map<std::string, CVValue> g_ChangeValues;

// re-entrancy guard: a hook handler that sends a packet re-enters
// parseOutgoing on this thread — never dispatch hooks twice at once
thread_local int t_HookDepth = 0;
struct HookDepthGuard {
    HookDepthGuard() { t_HookDepth++; }
    ~HookDepthGuard() { t_HookDepth--; }
};

LuaExecutor* selfFrom(lua_State* L) {
    LuaExecutor* self = nullptr;
    lua_getfield(L, LUA_REGISTRYINDEX, "__executor");
    if (lua_type(L, -1) == LUA_TLIGHTUSERDATA)
        self = (LuaExecutor*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return self;
}

// ── base64 + xor cipher (EpsHax roundtrip scheme) ────────────────────
const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64enc(const uint8_t* d, size_t n) {
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16;
        if (i + 1 < n) v |= (uint32_t)d[i + 1] << 8;
        if (i + 2 < n) v |= (uint32_t)d[i + 2];
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += (i + 1 < n) ? kB64[(v >> 6) & 63] : '=';
        out += (i + 2 < n) ? kB64[v & 63] : '=';
    }
    return out;
}

bool b64dec(const std::string& s, std::vector<uint8_t>& out) {
    int val = 0, valb = -8;
    out.clear();
    out.reserve(s.size());
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') break;
        const char* p = strchr(kB64, c);
        if (!p) return false;
        val = (val << 6) + (int)(p - kB64);
        valb += 6;
        if (valb >= 0) {
            out.push_back((uint8_t)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return true;
}

void xorCipher(uint8_t* d, size_t n, uint32_t key) {
    for (size_t i = 0; i < n; i++)
        d[i] ^= (uint8_t)(((key >> ((i & 3) * 8)) & 0xFF) ^ (0x5A + i * 31));
}

// ── script directory resolution (bothax docs: %appdata%\Growtopia\scripts)
std::vector<std::string> scriptDirs() {
    char appdata[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);
    std::vector<std::string> dirs;
    if (n > 0 && n < MAX_PATH)
        dirs.push_back(std::string(appdata) + "\\Growtopia\\scripts");
    dirs.push_back("C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\Script");
    return dirs;
}

bool fileExists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string resolveScriptFile(const std::string& name) {
    if (name.find(':') != std::string::npos || name.rfind("\\\\", 0) == 0)
        return name; // absolute
    for (auto& d : scriptDirs()) {
        std::string p = d + "\\" + name;
        if (fileExists(p)) return p;
    }
    return "";
}

// ── GameUpdatePacket (enetproxy gameupdatepacket_t layout, 56 bytes) ─
// 0:u8 type 1:u8 netid 2:u8 jump 3:u8 count 4:i32 player_flags
// 8:i32 item 12:i32 packet_flags 16:f32 struct_flags 20:i32 int_data
// 24:f32 x 28:f32 y 32:f32 xspeed 36:f32 yspeed 40:f32 particle_time
// 44:i32 state1 48:i32 state2 52:u32 data_size
void pushGUP(lua_State* L, const void* data, int len) {
    uint8_t p[56] = {};
    if (len > 0) memcpy(p, data, len > 56 ? 56 : len);
    auto gi32 = [&](int o) { int32_t v; memcpy(&v, p + o, 4); return (int)v; };
    auto gf32 = [&](int o) { float v; memcpy(&v, p + o, 4); return (double)v; };
    lua_newtable(L);
    auto seti = [&](const char* k, int v) { lua_pushinteger(L, v); lua_setfield(L, -2, k); };
    auto setf = [&](const char* k, double v) { lua_pushnumber(L, v); lua_setfield(L, -2, k); };
    seti("type", (int)p[0]);
    seti("dropped", (int)p[3]);
    seti("netid", gi32(4));      lua_pushinteger(L, gi32(4)); lua_setfield(L, -2, "player_flags");
    seti("snetid", gi32(8));     lua_pushinteger(L, gi32(8)); lua_setfield(L, -2, "secondnetid");
    seti("state", gi32(12));     lua_pushinteger(L, gi32(12)); lua_setfield(L, -2, "characterstate");
    seti("value", gi32(20));     lua_pushinteger(L, gi32(20)); lua_setfield(L, -2, "int_data");
    setf("x", gf32(24));         lua_pushnumber(L, gf32(24)); lua_setfield(L, -2, "pos_x");
    setf("y", gf32(28));
    setf("xspeed", gf32(32));
    setf("yspeed", gf32(36));
    seti("padding1", gi32(40));
    seti("px", gi32(44));        lua_pushinteger(L, gi32(44)); lua_setfield(L, -2, "tx");
    seti("py", gi32(48));        lua_pushinteger(L, gi32(48)); lua_setfield(L, -2, "ty");
    seti("extrasize", gi32(52));
}

// reads a GameUpdatePacket table into a 56-byte buffer (aliases supported)
bool readGUP(lua_State* L, int idx, uint8_t out[56]) {
    if (!lua_istable(L, idx)) return false;
    memset(out, 0, 56);
    auto geti = [&](std::initializer_list<const char*> keys, int def) -> int {
        for (const char* k : keys) {
            if (lua_getfield(L, idx, k) != LUA_TNIL) {
                int v = (int)lua_tointeger(L, -1);
                lua_pop(L, 1);
                return v;
            }
            lua_pop(L, 1);
        }
        return def;
    };
    auto getf = [&](std::initializer_list<const char*> keys, float def) -> float {
        for (const char* k : keys) {
            if (lua_getfield(L, idx, k) != LUA_TNIL) {
                float v = (float)lua_tonumber(L, -1);
                lua_pop(L, 1);
                return v;
            }
            lua_pop(L, 1);
        }
        return def;
    };
    int type = geti({"type"}, 0);
    int dropped = geti({"dropped"}, 0);
    int netid = geti({"netid", "player_flags"}, 0);
    int snetid = geti({"snetid", "secondnetid"}, 0);
    int state = geti({"state", "characterstate"}, 0);
    int value = geti({"value", "int_data"}, 0);
    float x = getf({"x", "pos_x"}, 0);
    float y = getf({"y", "pos_y"}, 0);
    float xs = getf({"xspeed"}, 0);
    float ys = getf({"yspeed"}, 0);
    int px = geti({"px", "tx", "int_x"}, 0);
    int py = geti({"py", "ty", "int_y"}, 0);
    out[0] = (uint8_t)(type & 0xFF);
    out[3] = (uint8_t)(dropped & 0xFF);
    memcpy(out + 4, &netid, 4);
    memcpy(out + 8, &snetid, 4);
    memcpy(out + 12, &state, 4);
    memcpy(out + 20, &value, 4);
    memcpy(out + 24, &x, 4);
    memcpy(out + 28, &y, 4);
    memcpy(out + 32, &xs, 4);
    memcpy(out + 36, &ys, 4);
    memcpy(out + 44, &px, 4);
    memcpy(out + 48, &py, 4);
    return true;
}

// FNV-1a (proton/hash.hpp semantics: seed overrides the offset basis)
uint32_t fnv1a32(const char* s, size_t n, uint32_t seed) {
    uint32_t h = seed;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x01000193u; }
    return h;
}
uint64_t fnv1a64(const char* s, size_t n, uint64_t seed) {
    uint64_t h = seed;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ull; }
    return h;
}

// OnVariant argument table — mirrors the tick-time OnVarlist parsing
// ([0]-based raw array + named keys), so var[0] = 'OnDialogRequest'
void pushVariantTable(lua_State* L, const std::string& text) {
    lua_newtable(L);
    std::istringstream stream(text);
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
}

int sendVariantThunk(lua_State* L) {
    const char* text = lua_tostring(L, lua_upvalueindex(1));
    if (text && *text) scanner::CallSendPacket(4, text);
    return 0;
}

} // namespace

// ═══ LuaExecutor shared table pushers ═══════════════════════════════

void LuaExecutor::pushTileFlags(lua_State* L, int raw) {
    unsigned v = (unsigned)raw & 0xFFFF;
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)v); lua_setfield(L, -2, "value");
    auto bit = [&](const char* k, unsigned mask) {
        lua_pushboolean(L, (v & mask) != 0); lua_setfield(L, -2, k);
    };
    bit("locked", TF_LOCKED);
    bit("spliced", TF_SPLICED);
    bit("dropseed", TF_DROPSEED);
    bit("tree", TF_TREE);
    bit("flipped", TF_FLIPPED);
    bit("enabled", TF_ENABLED);
    bit("public", TF_PUBLIC);
    bit("silenced", TF_SILENCED);
    bit("water", TF_WATER);
    bit("glue", TF_GLUE);
    bit("burn", TF_BURN);
    bit("red", TF_RED);
    bit("green", TF_GREEN);
    bit("blue", TF_BLUE);
}

void LuaExecutor::pushItemInfo(lua_State* L, const ItemInfo& it) {
    lua_newtable(L);
    lua_pushinteger(L, it.id); lua_setfield(L, -2, "id");
    lua_pushstring(L, it.name.c_str()); lua_setfield(L, -2, "name");
    lua_pushstring(L, it.filename.c_str()); lua_setfield(L, -2, "filename");
    lua_pushinteger(L, it.rarity); lua_setfield(L, -2, "rarity");
    lua_pushinteger(L, it.breakhit); lua_setfield(L, -2, "breakhit");
    lua_pushinteger(L, it.growtime); lua_setfield(L, -2, "growtime");
    lua_pushinteger(L, it.item_type); lua_setfield(L, -2, "type");
    lua_pushinteger(L, it.coltype); lua_setfield(L, -2, "coltype");
    lua_pushinteger(L, it.clothingtype); lua_setfield(L, -2, "clothingtype");
    lua_pushinteger(L, it.visualstyle); lua_setfield(L, -2, "visualstyle");
    lua_pushinteger(L, it.texturex); lua_setfield(L, -2, "texturex");
    lua_pushinteger(L, it.texturey); lua_setfield(L, -2, "texturey");
    lua_pushinteger(L, it.flags); lua_setfield(L, -2, "flags");
    // legacy EpsHax/GrowPai keys
    lua_pushinteger(L, it.item_type); lua_setfield(L, -2, "item_type");
    lua_pushinteger(L, it.growth); lua_setfield(L, -2, "growth");
    lua_pushinteger(L, it.size); lua_setfield(L, -2, "size");
}

void LuaExecutor::pushAvatar(lua_State* L, const PlayerData& p, bool isSelf) {
    (void)isSelf;
    lua_newtable(L);
    lua_pushstring(L, p.name.c_str()); lua_setfield(L, -2, "name");
    lua_pushstring(L, p.world.c_str()); lua_setfield(L, -2, "world");
    lua_pushstring(L, p.country.c_str()); lua_setfield(L, -2, "country");
    lua_pushinteger(L, p.netid); lua_setfield(L, -2, "netid");
    lua_pushinteger(L, p.userid); lua_setfield(L, -2, "userid");
    lua_pushinteger(L, p.gems); lua_setfield(L, -2, "gems");
    lua_pushboolean(L, p.facing_left); lua_setfield(L, -2, "isleft");
    lua_pushboolean(L, p.facing_left); lua_setfield(L, -2, "facing_left");
    lua_pushboolean(L, p.invisible); lua_setfield(L, -2, "invisible");
    lua_pushboolean(L, p.mstate); lua_setfield(L, -2, "mstate");
    lua_pushboolean(L, p.smstate); lua_setfield(L, -2, "smstate");
    lua_pushinteger(L, p.flags); lua_setfield(L, -2, "flags");
    lua_pushinteger(L, p.flags2); lua_setfield(L, -2, "flags2");
    lua_pushnumber(L, p.pos_x); lua_setfield(L, -2, "pos_x");
    lua_pushnumber(L, p.pos_y); lua_setfield(L, -2, "pos_y");
    lua_pushinteger(L, p.tile_x); lua_setfield(L, -2, "tile_x");
    lua_pushinteger(L, p.tile_y); lua_setfield(L, -2, "tile_y");
    lua_pushnumber(L, p.size_x); lua_setfield(L, -2, "size_x");
    lua_pushnumber(L, p.size_y); lua_setfield(L, -2, "size_y");
    lua_newtable(L);
    lua_pushnumber(L, p.pos_x); lua_setfield(L, -2, "x");
    lua_pushnumber(L, p.pos_y); lua_setfield(L, -2, "y");
    lua_setfield(L, -2, "pos");
}

// ═══ bothax functions ═══════════════════════════════════════════════

int LuaExecutor::lua_ChangeValue(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    CVValue v;
    if (lua_isboolean(L, 2)) { v.t = 0; v.b = lua_toboolean(L, 2); }
    else if (lua_isnumber(L, 2)) { v.t = 1; v.n = lua_tonumber(L, 2); }
    else { v.t = 2; v.s = luaL_optstring(L, 2, ""); }
    g_ChangeValues[name] = v;
    debugLog("[CHANGEVALUE] " + std::string(name) + " set (type " +
             std::to_string(v.t) + ")");
    return 0;
}

int LuaExecutor::lua_Encrypt(lua_State* L) {
    size_t n = 0;
    const char* text = luaL_checklstring(L, 1, &n);
    uint32_t key = (uint32_t)luaL_optinteger(L, 2, 0x5A5A5A5A);
    std::vector<uint8_t> buf((const uint8_t*)text, (const uint8_t*)text + n);
    xorCipher(buf.data(), buf.size(), key);
    std::string enc = b64enc(buf.data(), buf.size());
    lua_pushlstring(L, enc.c_str(), enc.size());
    return 1;
}

static bool decryptArg(lua_State* L, int idx, std::string& out) {
    size_t n = 0;
    const char* enc = luaL_checklstring(L, idx, &n);
    std::vector<uint8_t> buf;
    if (!b64dec(std::string(enc, n), buf)) return false;
    xorCipher(buf.data(), buf.size(), 0x5A5A5A5A);
    out.assign((const char*)buf.data(), buf.size());
    return true;
}

int LuaExecutor::lua_LoadEncrypt(lua_State* L) {
    std::string plain;
    if (!decryptArg(L, 1, plain)) {
        consoleLog("[ERROR] LoadEncrypt: bad encrypted payload");
        return 0;
    }
    if (luaL_loadbuffer(L, plain.c_str(), plain.size(), "enc") != 0) {
        const char* err = lua_tostring(L, -1);
        consoleLog("[ERROR] LoadEncrypt: " + std::string(err ? err : "?"));
        lua_pop(L, 1);
        return 0;
    }
    startThread(L, lua_gettop(L), 0); // run as coroutine (Sleep-safe)
    return 0;
}

int LuaExecutor::lua_EncryptFile(lua_State* L) {
    const char* fname = luaL_checkstring(L, 1);
    uint32_t key = (uint32_t)luaL_optinteger(L, 2, 0x5A5A5A5A);
    std::string path = resolveScriptFile(fname);
    if (path.empty()) {
        consoleLog("[ERROR] EncryptFile: not found: " + std::string(fname));
        return 0;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) { consoleLog("[ERROR] EncryptFile: open failed " + path); return 0; }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    std::vector<uint8_t> buf(data.begin(), data.end());
    xorCipher(buf.data(), buf.size(), key);
    std::string enc = b64enc(buf.data(), buf.size());
    std::string outPath = path + "_enc";
    std::ofstream out(outPath, std::ios::binary);
    if (!out.is_open()) { consoleLog("[ERROR] EncryptFile: write failed " + outPath); return 0; }
    out << enc;
    out.close();
    consoleLog("[INFO] EncryptFile: wrote " + outPath);
    return 0;
}

int LuaExecutor::lua_LoadEncryptedFile(lua_State* L) {
    const char* fname = luaL_checkstring(L, 1);
    std::string path = resolveScriptFile(fname);
    if (path.empty()) path = resolveScriptFile(std::string(fname) + "_enc");
    if (path.empty()) {
        consoleLog("[ERROR] LoadEncryptedFile: not found: " + std::string(fname));
        return 0;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) { consoleLog("[ERROR] LoadEncryptedFile: open failed " + path); return 0; }
    std::string enc((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    std::vector<uint8_t> buf;
    if (!b64dec(enc, buf)) { consoleLog("[ERROR] LoadEncryptedFile: bad payload " + path); return 0; }
    xorCipher(buf.data(), buf.size(), 0x5A5A5A5A);
    std::string plain((const char*)buf.data(), buf.size());
    if (luaL_loadbuffer(L, plain.c_str(), plain.size(), path.c_str()) != 0) {
        const char* err = lua_tostring(L, -1);
        consoleLog("[ERROR] LoadEncryptedFile: " + std::string(err ? err : "?"));
        lua_pop(L, 1);
        return 0;
    }
    startThread(L, lua_gettop(L), 0);
    return 0;
}

int LuaExecutor::lua_GetCamera(lua_State* L) {
    float px = 0, py = 0;
    {
        auto& gs = GameState::instance();
        std::lock_guard<std::mutex> lk(gs.mtx);
        px = gs.localPlayer.pos_x;
        py = gs.localPlayer.pos_y;
    }
    double rx = 1360, ry = 768;
    HWND hwnd = g_GameHWND;
    if (hwnd) {
        RECT rc;
        if (GetClientRect(hwnd, &rc)) { rx = (double)(rc.right - rc.left); ry = (double)(rc.bottom - rc.top); }
    }
    lua_newtable(L);
    auto vec = [&](const char* k, double x, double y) {
        lua_newtable(L);
        lua_pushnumber(L, x); lua_setfield(L, -2, "x");
        lua_pushnumber(L, y); lua_setfield(L, -2, "y");
        lua_setfield(L, -2, k);
    };
    vec("pos", px, py);
    vec("center", px, py);
    lua_pushnumber(L, 1.0); lua_setfield(L, -2, "scale");
    vec("resolution", rx, ry);
    return 1;
}

int LuaExecutor::lua_GetClient(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    lua_newtable(L);
    lua_pushstring(L, gs.server_addr.c_str()); lua_setfield(L, -2, "address");
    lua_pushinteger(L, gs.server_port); lua_setfield(L, -2, "port");
    lua_pushinteger(L, gs.ping_ms); lua_setfield(L, -2, "ping");
    return 1;
}

int LuaExecutor::lua_GetItemByIDSafe(lua_State* L) {
    int id = (int)luaL_checkinteger(L, 1);
    const ItemInfo* it = itemdb::get(id);
    if (it) pushItemInfo(L, *it);
    else { ItemInfo unk; unk.name = "Unknown"; unk.id = id; pushItemInfo(L, unk); }
    return 1;
}

int LuaExecutor::lua_GetItemByName(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    const ItemInfo* it = itemdb::byName(name);
    if (!it) return 0; // nil — not found
    pushItemInfo(L, *it);
    return 1;
}

int LuaExecutor::lua_GetItemInfoList(lua_State* L) {
    itemdb::ensureLoaded();
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& kv : gs.itemDatabase) {
        pushItemInfo(L, kv.second);
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_GetItemsByPartialName(lua_State* L) {
    const char* needle = luaL_checkstring(L, 1);
    auto list = itemdb::partial(needle);
    lua_newtable(L);
    int idx = 1;
    for (auto* it : list) {
        pushItemInfo(L, *it);
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_GetNPC(lua_State* L) {
    int id = (int)luaL_checkinteger(L, 1);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    for (auto& n : gs.npcs) {
        if (n.id == id) {
            lua_newtable(L);
            lua_pushinteger(L, n.id); lua_setfield(L, -2, "id");
            lua_pushinteger(L, n.type); lua_setfield(L, -2, "type");
            lua_newtable(L);
            lua_pushnumber(L, n.pos_x); lua_setfield(L, -2, "x");
            lua_pushnumber(L, n.pos_y); lua_setfield(L, -2, "y");
            lua_setfield(L, -2, "pos");
            lua_newtable(L);
            lua_pushnumber(L, n.target_x); lua_setfield(L, -2, "x");
            lua_pushnumber(L, n.target_y); lua_setfield(L, -2, "y");
            lua_setfield(L, -2, "target");
            return 1;
        }
    }
    return 0; // nil
}

int LuaExecutor::lua_GetNPCList(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& n : gs.npcs) {
        lua_newtable(L);
        lua_pushinteger(L, n.id); lua_setfield(L, -2, "id");
        lua_pushinteger(L, n.type); lua_setfield(L, -2, "type");
        lua_newtable(L);
        lua_pushnumber(L, n.pos_x); lua_setfield(L, -2, "x");
        lua_pushnumber(L, n.pos_y); lua_setfield(L, -2, "y");
        lua_setfield(L, -2, "pos");
        lua_newtable(L);
        lua_pushnumber(L, n.target_x); lua_setfield(L, -2, "x");
        lua_pushnumber(L, n.target_y); lua_setfield(L, -2, "y");
        lua_setfield(L, -2, "target");
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_GetObjectList(lua_State* L) {
    return lua_GetObjects(L);
}

int LuaExecutor::lua_GetPlayer(lua_State* L) {
    int netid = (int)luaL_checkinteger(L, 1);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    for (auto& p : gs.players) {
        if (p.netid == netid) { pushAvatar(L, p, false); return 1; }
    }
    return 0; // nil
}

int LuaExecutor::lua_GetPlayerInfo(lua_State* L) {
    SyncGameCaches(false);
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    lua_newtable(L);
    lua_pushinteger(L, gs.localPlayer.gems); lua_setfield(L, -2, "gems");
    lua_newtable(L); // backpack
    lua_newtable(L); // priority — order of backpack ids (no priority data in game cache)
    int idx = 1;
    for (auto& item : gs.inventory) {
        lua_pushinteger(L, item.id);
        lua_rawseti(L, -2, idx++);
    }
    lua_setfield(L, -2, "priority");
    lua_pushinteger(L, (int)gs.inventory.size()); lua_setfield(L, -2, "size");
    lua_pushinteger(L, gs.localPlayer.item); lua_setfield(L, -2, "selected");
    lua_setfield(L, -2, "backpack");
    return 1;
}

int LuaExecutor::lua_GetPlayerItems(lua_State* L) {
    return lua_GetPlayerInfo(L);
}

int LuaExecutor::lua_GetPlayerList(lua_State* L) {
    auto& gs = GameState::instance();
    std::lock_guard<std::mutex> lk(gs.mtx);
    lua_newtable(L);
    int idx = 1;
    for (auto& p : gs.players) {
        if (p.netid == gs.localPlayer.netid) continue; // excluding yourself
        pushAvatar(L, p, false);
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

int LuaExecutor::lua_Hash32(lua_State* L) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, 1, &n);
    uint32_t seed = lua_isnoneornil(L, 2) ? 0x811c9dc5u : (uint32_t)luaL_checkinteger(L, 2);
    lua_pushinteger(L, (lua_Integer)fnv1a32(s, n, seed));
    return 1;
}

int LuaExecutor::lua_Hash64(lua_State* L) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, 1, &n);
    uint64_t seed = lua_isnoneornil(L, 2) ? 0xcbf29ce484222325ull
                                          : (uint64_t)(lua_Integer)luaL_checkinteger(L, 2);
    lua_pushinteger(L, (lua_Integer)fnv1a64(s, n, seed));
    return 1;
}

int LuaExecutor::lua_RequestJoinWorld(lua_State* L) {
    const char* world = luaL_checkstring(L, 1);
    // GTPS join: newline-framed first line + name + invitedWorld (a
    // pipe-framed "action|join_request|WORLD" is rejected server-side:
    // first line must match ^action\|join_request$ exactly).
    std::string pkt = "action|join_request\nname|" + std::string(world) +
                      "\ninvitedWorld|0";
    scanner::CallSendPacket(3, pkt.c_str());
    debugLog("[JOIN] RequestJoinWorld: " + std::string(world));
    return 0;
}

int LuaExecutor::lua_RunDelayed(lua_State* L) {
    int ms = (int)luaL_checkinteger(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    LuaExecutor* self = selfFrom(L);
    if (!self) return 0;
    int nargs = lua_gettop(L) - 2;
    DelayedInfo d;
    d.fireAt = g_currentTime + (ms > 0 ? ms : 0) / 1000.0f;
    lua_pushvalue(L, 2);
    d.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    for (int i = 1; i <= nargs; i++) {
        lua_pushvalue(L, 2 + i);
        d.argRefs.push_back(luaL_ref(L, LUA_REGISTRYINDEX));
    }
    self->delayed.push_back(std::move(d));
    return 0;
}

int LuaExecutor::lua_SetItemSelected(lua_State* L) {
    int id = (int)luaL_checkinteger(L, 1);
    // GameUpdatePacket { type = 10 (item activate/select), value = itemid }
    uint8_t p[56] = {};
    p[0] = 10;
    memcpy(p + 20, &id, 4);
    scanner::CallSendPacketBin(4, p, sizeof p);
    {
        auto& gs = GameState::instance();
        std::lock_guard<std::mutex> lk(gs.mtx);
        gs.localPlayer.item = id;
    }
    debugLog("[ITEM] SetItemSelected: " + std::to_string(id));
    return 0;
}

// SetTileFlags(x, y, int|TileFlags table) — writes the u16 flag word at
// tile + idx*0xF0 + 0x52 (same word SyncGameCaches reads) and updates the
// gs.tiles cache. Direct same-process write; POD-only SEH wrapper.
namespace {
bool tileFlagRw(uintptr_t addr, uint16_t* v, bool write) {
    __try {
        if (write) *(uint16_t*)addr = *v;
        else *v = *(uint16_t*)addr;
        return true;
    } __except (1) {
        return false;
    }
}
} // namespace

int LuaExecutor::lua_SetTileFlags(lua_State* L) {
    int x = (int)luaL_checkinteger(L, 1);
    int y = (int)luaL_checkinteger(L, 2);
    uint16_t nv = 0;
    bool haveTable = lua_istable(L, 3);
    if (haveTable) {
        if (lua_getfield(L, 3, "value") != LUA_TNIL)
            nv = (uint16_t)(int)lua_tointeger(L, -1);
        lua_pop(L, 1);
        auto bit = [&](const char* k, unsigned mask) {
            if (lua_getfield(L, 3, k) == LUA_TBOOLEAN) {
                if (lua_toboolean(L, -1)) nv = (uint16_t)(nv | mask);
                else nv = (uint16_t)(nv & ~mask);
            }
            lua_pop(L, 1);
        };
        bit("locked", TF_LOCKED);   bit("spliced", TF_SPLICED);
        bit("dropseed", TF_DROPSEED); bit("tree", TF_TREE);
        bit("flipped", TF_FLIPPED); bit("enabled", TF_ENABLED);
        bit("public", TF_PUBLIC);   bit("silenced", TF_SILENCED);
        bit("water", TF_WATER);     bit("glue", TF_GLUE);
        bit("burn", TF_BURN);       bit("red", TF_RED);
        bit("green", TF_GREEN);     bit("blue", TF_BLUE);
    } else {
        nv = (uint16_t)(int)luaL_checkinteger(L, 3);
    }
    SyncGameCaches(false);
    uintptr_t base = g_TileBegin.load(std::memory_order_relaxed);
    int w = g_TileW.load(std::memory_order_relaxed);
    int h = g_TileH.load(std::memory_order_relaxed);
    bool ok = false;
    if (base && w > 0 && h > 0 && x >= 0 && y >= 0 && x < w && y < h) {
        uintptr_t addr = base + ((uintptr_t)(y * w + x)) * 0xF0 + 0x52;
        ok = tileFlagRw(addr, &nv, true);
    }
    if (ok) {
        auto& gs = GameState::instance();
        std::lock_guard<std::mutex> lk(gs.mtx);
        if (y < (int)gs.tiles.size() && x < (int)gs.tiles[y].size())
            gs.tiles[y][x].flags = nv;
        debugLog("[TILE] SetTileFlags(" + std::to_string(x) + "," +
                 std::to_string(y) + ") = " + std::to_string(nv));
    } else {
        consoleLog("[ERROR] SetTileFlags: no tile base / out of range (" +
                   std::to_string(x) + "," + std::to_string(y) + ")");
    }
    return 0;
}

// bothax SendVariantList(var [, netid] [, delay]) — [0]-based variant
// array, optional ms delay before the type-4 text send.
int LuaExecutor::lua_SendVariantListBx(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    int netid = (int)luaL_optinteger(L, 2, -1);
    int delay = (int)luaL_optinteger(L, 3, 0);
    // bothax VariantList is [0]-based; tolerate 1-based tables when slot 0
    // is missing (legacy GrowPai scripts index from 1)
    int start = 0;
    if (lua_rawgeti(L, 1, 0) == LUA_TNIL) {
        lua_pop(L, 1);
        start = (lua_rawgeti(L, 1, 1) != LUA_TNIL) ? 1 : -1;
        lua_pop(L, 1);
        if (start < 0) return 0;
    } else {
        lua_pop(L, 1);
    }
    std::string out;
    for (int i = start; ; i++) {
        if (lua_rawgeti(L, 1, i) == LUA_TNIL) { lua_pop(L, 1); break; }
        std::string piece;
        if (lua_isstring(L, -1)) piece = lua_tostring(L, -1);
        else if (lua_isnumber(L, -1)) {
            // keep integral numbers clean, floats with 9 significant digits
            double d = lua_tonumber(L, -1);
            char b[64];
            if (d == (double)(long long)d) snprintf(b, sizeof b, "%lld", (long long)d);
            else snprintf(b, sizeof b, "%.9g", d);
            piece = b;
        } else if (lua_isboolean(L, -1)) piece = lua_toboolean(L, -1) ? "true" : "false";
        lua_pop(L, 1);
        if (i > start) out += "\n";
        out += piece;
    }
    if (out.empty()) return 0;
    if (netid != -1 && netid != 0)
        debugLog("[VARIANT] netid=" + std::to_string(netid) + " (text send: not applied)");
    if (delay <= 0) {
        scanner::CallSendPacket(4, out.c_str());
    } else {
        LuaExecutor* self = selfFrom(L);
        if (!self) return 0;
        lua_pushlstring(L, out.c_str(), out.size());
        lua_pushinteger(L, 4);
        lua_pushcclosure(L, sendVariantThunk, 2);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        self->delayed.push_back({g_currentTime + delay / 1000.0f, ref, {}});
    }
    debugLog("[VARIANT] SendVariantList: " + out.substr(0, 80));
    return 0;
}

// bothax SendPacketRaw(to_client, GameUpdatePacket) — legacy
// SendPacketRaw(string, len) is dispatched in lua_SendPacketRaw.
int LuaExecutor::lua_SendPacketRawBx(lua_State* L) {
    bool toClient = lua_toboolean(L, 1);
    uint8_t p[56];
    if (!readGUP(L, 2, p)) {
        consoleLog("[ERROR] SendPacketRaw: arg 2 must be a packet table");
        return 0;
    }
    if (!toClient) {
        scanner::CallSendPacketBin(4, p, sizeof p);
    } else {
        // simulate inbound: surface it as an OnTankPacket event
        int ptype = p[0];
        if (ptype != 0) {
            PacketEvent ev;
            ev.type = "OnTankPacket";
            ev.packet_type = ptype;
            memcpy(&ev.netid, p + 4, 4);
            memcpy(&ev.flags, p + 12, 4);
            memcpy(&ev.int_data, p + 20, 4);
            memcpy(&ev.pos_x, p + 24, 4);
            memcpy(&ev.pos_y, p + 28, 4);
            GameState::instance().pushEvent(ev);
        }
    }
    debugLog("[PACKET] SendPacketRaw bothax type=" + std::to_string(p[0]) +
             (toClient ? " (client)" : " (server)"));
    return 0;
}

// bothax MakeRequest(url [, method [, headers [, content [, timeout_ms]]]])
// → HttpResponse { status, error, method, content } — synchronous.
int LuaExecutor::lua_MakeRequestBx(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    const char* method = luaL_optstring(L, 2, "GET");
    int timeout = (int)luaL_optinteger(L, 5, 10000);
    std::string content;
    bool hasContent = lua_isstring(L, 4);
    if (hasContent) content = lua_tostring(L, 4);

    std::string methodS = method;
    for (auto& c : methodS) c = (char)toupper((unsigned char)c);

    // headers table → "k: v\r\n"
    std::wstring extraHeaders;
    if (lua_istable(L, 3)) {
        lua_pushnil(L);
        while (lua_next(L, 3) != 0) {
            if (lua_isstring(L, -2) && lua_isstring(L, -1)) {
                std::string k = lua_tostring(L, -2);
                std::string v = lua_tostring(L, -1);
                std::wstring wk(k.begin(), k.end()), wv(v.begin(), v.end());
                extraHeaders += wk; extraHeaders += L": "; extraHeaders += wv;
                extraHeaders += L"\r\n";
            }
            lua_pop(L, 1);
        }
    }

    int status = 0;
    bool error = true;
    std::string body;

    std::wstring wmethod(methodS.begin(), methodS.end());
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = {};
    wchar_t path[4096] = {};
    wchar_t extra[4096] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = (DWORD)_countof(host);
    uc.lpszUrlPath = path;  uc.dwUrlPathLength = (DWORD)_countof(path);
    uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = (DWORD)_countof(extra);

    std::wstring wurl;
    { int wl = MultiByteToWideChar(CP_UTF8, 0, url, -1, nullptr, 0);
      wurl.resize(wl > 0 ? wl : 0);
      if (wl > 0) MultiByteToWideChar(CP_UTF8, 0, url, -1, &wurl[0], wl); }

    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    DWORD openFlags = WINHTTP_FLAG_SECURE;
    if (WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.size(), 0, &uc)) {
        port = uc.nPort;
        openFlags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    } else {
        debugLog("[HTTP] MakeRequest: URL parse failed: " + std::string(url));
    }

    HINTERNET ses = WinHttpOpen(L"EpsHax/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        ses = WinHttpOpen(L"EpsHax/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (ses) {
        WinHttpSetTimeouts(ses, timeout, timeout, timeout, timeout);
        HINTERNET con = WinHttpConnect(ses, host, port, 0);
        if (con) {
            std::wstring full(path);
            full += extra;
            HINTERNET req = WinHttpOpenRequest(con, wmethod.c_str(), full.c_str(),
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags);
            if (req) {
                if (!extraHeaders.empty())
                    WinHttpAddRequestHeaders(req, extraHeaders.c_str(),
                        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
                void* sendBuf = hasContent ? (void*)content.data() : WINHTTP_NO_REQUEST_DATA;
                DWORD sendLen = hasContent ? (DWORD)content.size() : 0;
                if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        sendBuf, sendLen, sendLen, 0) &&
                    WinHttpReceiveResponse(req, 0)) {
                    DWORD code = 0, csz = sizeof(code);
                    if (WinHttpQueryHeaders(req,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            NULL, &code, &csz, NULL))
                        status = (int)code;
                    error = (status <= 0);
                    char buf[8192];
                    DWORD rd = 0;
                    while (WinHttpReadData(req, buf, sizeof buf, &rd) && rd > 0) {
                        body.append(buf, rd);
                        if (body.size() > 8u * 1024u * 1024u) break; // 8MB cap
                    }
                } else {
                    debugLog("[HTTP] MakeRequest: request failed (" +
                             std::to_string(GetLastError()) + ") " + url);
                }
                WinHttpCloseHandle(req);
            }
            WinHttpCloseHandle(con);
        }
        WinHttpCloseHandle(ses);
    } else {
        debugLog("[HTTP] MakeRequest: WinHttpOpen failed " + std::to_string(GetLastError()));
    }

    lua_newtable(L);
    lua_pushinteger(L, status);     lua_setfield(L, -2, "status");
    lua_pushboolean(L, error);      lua_setfield(L, -2, "error");
    lua_pushstring(L, methodS.c_str()); lua_setfield(L, -2, "method");
    lua_pushlstring(L, body.c_str(), body.size()); lua_setfield(L, -2, "content");
    debugLog("[HTTP] MakeRequest " + methodS + " " + url + " -> " + std::to_string(status));
    return 1;
}

// ═══ LuaHooks sync dispatch bridge ══════════════════════════════════
// Called from hook.cpp packet paths (NOT holding gs.mtx — verified).
// g_LuaMtx serializes against tick/execute/stop; t_HookDepth (thread_local)
// stops a handler's own SendPacket from re-dispatching hooks on this
// thread. Each matching callback runs; blocked = OR of `return true`.

namespace LuaHooks {

namespace {
LuaExecutor* ready() {
    LuaExecutor* ex = g_executor;
    if (!ex || !ex->isRunning()) return nullptr;
    return ex;
}

// run every callback of `ev`; returns true if any returned true.
// Snapshot of (ref,name) pairs: handlers may AddHook/RemoveHook re-entrantly
// (reallocating `callbacks` while a live iterator would be invalid).
bool runHooks(lua_State* L, const char* ev,
              const std::function<int(lua_State*)>& pushArgs) {
    LuaExecutor* ex = g_executor;
    bool blocked = false;
    std::vector<std::pair<int, std::string>> refs;
    for (auto& cb : ex->callbacks)
        if (cb.type == ev) refs.emplace_back(cb.ref, cb.name);
    for (auto& [ref, cbName] : refs) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        if (!lua_isfunction(L, -1)) { lua_pop(L, 1); continue; }
        int nargs = pushArgs(L);            // pushes args ON TOP of fn
        if (lua_pcall(L, nargs, 1, 0) != 0) {
            const char* err = lua_tostring(L, -1);
            consoleLog(std::string("[ERROR] ") + ev + " hook '" + cbName + "': " +
                       (err ? err : "?"));
            lua_pop(L, 1);
            continue;
        }
        if (lua_isboolean(L, -1) && lua_toboolean(L, -1)) blocked = true;
        lua_pop(L, 1);
    }
    return blocked;
}
} // namespace

bool dispatchVariant(const std::string& text) {
    static int s_dv = 0;
    LuaExecutor* ex = ready();
    if (!ex) {
        if (s_dv < 4) { s_dv++; debugLog("[DSPVAR] skip: executor not ready"); }
        return false;
    }
    if (t_HookDepth > 0) {
        if (s_dv < 4) { s_dv++; debugLog("[DSPVAR] skip: depth=" + std::to_string(t_HookDepth)); }
        return false;
    }
    HookDepthGuard guard;
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    lua_State* L = ex->getLuaState();
    if (!L) return false;
    int nvar = 0;
    for (auto& cb : ex->callbacks)
        if (cb.type == "OnVariant") nvar++;
    if (nvar > 0 && s_dv < 8) {
        s_dv++;
        debugLog("[DSPVAR] running with OnVariant hooks=" + std::to_string(nvar));
    }
    return runHooks(L, "OnVariant", [&text](lua_State* L2) {
        pushVariantTable(L2, text);   // [0]-based array + named keys
        return 1;
    });
}

bool dispatchSendPacket(int ptype, const std::string& text) {
    LuaExecutor* ex = ready();
    if (!ex) return false;
    if (t_HookDepth > 0) return false;
    HookDepthGuard guard;
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    lua_State* L = ex->getLuaState();
    if (!L) return false;
    return runHooks(L, "OnSendPacket", [ptype, &text](lua_State* L2) {
        lua_pushinteger(L2, ptype);
        lua_pushlstring(L2, text.c_str(), text.size());
        return 2;
    });
}

bool dispatchSendPacketRaw(const void* data, int len) {
    LuaExecutor* ex = ready();
    if (!ex) return false;
    if (t_HookDepth > 0) return false;
    HookDepthGuard guard;
    std::lock_guard<std::recursive_mutex> lk(g_LuaMtx);
    lua_State* L = ex->getLuaState();
    if (!L) return false;
    return runHooks(L, "OnSendPacketRaw", [data, len](lua_State* L2) {
        pushGUP(L2, data, len);       // GameUpdatePacket table
        return 1;
    });
}

} // namespace LuaHooks
