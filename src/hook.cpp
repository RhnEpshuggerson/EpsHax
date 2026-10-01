#include "hook.h"
#include "lua_api.h"
#include <intrin.h>

#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_opengl3.h>
#include <gl/GL.h>

#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <vector>
#include <chrono>
#include <sstream>
#include <windows.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ── Globals ──────────────────────────────────────────────────────────
wglSwapBuffers_t o_wglSwapBuffers = nullptr;
bool g_Initialized = false;
HWND g_GameHWND = nullptr;
bool g_MenuOpen = false;
WNDPROC oWndProc = nullptr;

// ── F1 toggle via GetAsyncKeyState (no global hook — avoids Themida detection) ──
static bool g_F1WasDown = false;

std::unordered_set<std::string> g_luaCommands;

// ── Clipboard ────────────────────────────────────────────────────────
static const char* ClipGetText(void*) {
    if (!OpenClipboard(nullptr)) return "";
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return ""; }
    char* text = (char*)GlobalLock(hData);
    if (!text) { CloseClipboard(); return ""; }
    static std::string s; s = text;
    GlobalUnlock(hData); CloseClipboard();
    return s.c_str();
}

static void ClipSetText(void*, const char* text) {
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    memcpy(GlobalLock(hMem), text, len);
    GlobalUnlock(hMem);
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
}

// ── WndProc hook ─────────────────────────────────────────────────────
LRESULT CALLBACK hkWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_MenuOpen) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return 1;

        switch (msg) {
            case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK: SetCapture(hWnd); return 1;
            case WM_LBUTTONUP: ReleaseCapture(); return 1;
            case WM_RBUTTONDOWN: case WM_RBUTTONDBLCLK: case WM_RBUTTONUP: return 1;
            case WM_MOUSEMOVE: case WM_MOUSEWHEEL: return 1;
            case WM_KEYDOWN: case WM_KEYUP: case WM_SYSKEYDOWN: case WM_SYSKEYUP:
            case WM_CHAR: case WM_UNICHAR:
                return 1;
        }
    }

    return CallWindowProcW(oWndProc, hWnd, msg, wParam, lParam);
}

// ── UI State ─────────────────────────────────────────────────────────
static bool showConsole = true;
static bool showDebug = true;
static bool showSettings = false;
static bool autoScroll = true;
static bool debugPackets = false;
static bool debugCallbacks = true;
static bool debugTimer = true;
static bool debugPathfinding = false;
static bool debugInventory = false;
static bool debugPlayers = false;
static float g_TickInterval = 1.0f;
static char scriptBuf[262144] = "";
extern "C" __declspec(dllexport) char* EpsHax_GetScriptBuf() { return scriptBuf; }

// Headless execute: remote tooling writes scriptBuf via EpsHax_GetScriptBuf
// then CreateRemoteThread()s this export — runs the buffer like the menu
// Execute button, without touching the UI. No-op until hook init finished.
extern "C" __declspec(dllexport) void EpsHax_ExecuteScriptBuf() {
    LuaExecutor* exec = g_executor;
    if (!exec) return;
    std::string script(scriptBuf);
    if (script.empty()) return;
    debugLog("[SYSTEM] EpsHax_ExecuteScriptBuf (" + std::to_string(script.size()) + " bytes)");
    std::thread([exec, script]() { exec->execute(script); }).detach();
}
LuaExecutor* g_executor = nullptr;

// ── GameState ────────────────────────────────────────────────────────
GameState& GameState::instance() {
    static GameState inst;
    return inst;
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static std::map<std::string, std::string> parseTextLines(const std::string& text) {
    std::map<std::string, std::string> kv;
    std::istringstream stream(text);
    std::string line;
    int idx = 0;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) continue;
        size_t pipe = line.find('|');
        if (pipe != std::string::npos) {
            std::string key = trim(line.substr(0, pipe));
            std::string val = trim(line.substr(pipe + 1));
            kv[key] = val;
        } else {
            kv["_" + std::to_string(idx)] = line;
        }
        idx++;
    }
    return kv;
}

static float safeFloat(const std::string& s, float def = 0) {
    try { return std::stof(s); } catch (...) { return def; }
}

static int safeInt(const std::string& s, int def = 0) {
    try { return std::stoi(s); } catch (...) { return def; }
}

void GameState::parseTextPacket(const std::string& text, bool incoming) {
    if (text.size() < 4) return;

    // NUL-separated multi-record payloads (e.g. two spawn records in one
    // tank packet) — each record must be parsed independently or record 2
    // gets glued into record 1's last value and is lost.
    if (text.find('\0') != std::string::npos) {
        size_t start = 0;
        while (start < text.size()) {
            size_t z = text.find('\0', start);
            std::string rec = (z == std::string::npos)
                ? text.substr(start) : text.substr(start, z - start);
            if (rec.size() >= 4) parseTextPacket(rec, incoming);
            if (z == std::string::npos) break;
            start = z + 1;
        }
        return;
    }

    // bothax AddHook('OnVariant') — synchronous, return true suppresses
    // EpsHax-side processing of this variant (network-level dialog blocking
    // is not available in the recv path — see LuaHooks docs)
    if (incoming && LuaHooks::dispatchVariant(text)) return;

    auto kv = parseTextLines(text);
    std::string action = kv.count("action") ? kv["action"] : "";

    // world_name key may appear on any action (this client has no
    // set_field_init) — capture globally.
    if (incoming && kv.count("world_name") && !kv["world_name"].empty()) {
        std::string wn = kv["world_name"];
        size_t br = wn.find(" [");            // strip " [" badge artifact
        if (br != std::string::npos) wn.erase(br);
        std::lock_guard<std::mutex> lock(mtx);
        localPlayer.world = wn;
        debugLog("[WORLD] world_name=" + localPlayer.world);
    }

    // World identity also arrives only in the log line:
    //   action|log  msg|`oWorld `wAFKWINDY [...] entered.
    if (incoming && action == "log" && kv.count("msg")) {
        const std::string& m = kv["msg"];
        size_t wp = m.find("World `");
        if (wp != std::string::npos && wp + 9 < m.size() && m[wp + 6] == '`') {
            size_t st = wp + 8;   // "World `" + color char (e.g. `w) -> name
            size_t e = m.find('`', st);
            if (e != std::string::npos && e > st && e - st < 32) {
                std::string world = m.substr(st, e - st);
                size_t br = world.find(" ["); // strip " [" badge artifact
                if (br != std::string::npos) world.erase(br);
                std::lock_guard<std::mutex> lock(mtx);
                if (localPlayer.world != world) {
                    localPlayer.world = world;
                    debugLog("[WORLD] set from log: " + world);
                }
            }
        }
    }

    // Always log incoming text packet action for debugging
    if (incoming) {
        std::string preview = text.substr(0, 150);
        for (auto& c : preview) { if (c == '\n') c = '|'; }
        consoleLog("[IN] action=[" + action + "] " + preview);
    }

    if (action == "spawn" || action == "on_spawn") {
        std::lock_guard<std::mutex> lock(mtx);
        if (incoming) {
            PlayerData p;
            p.name = kv.count("name") ? kv["name"] : "Unknown";
            p.country = kv.count("country") ? kv["country"] : "us";
            p.netid = safeInt(kv.count("NetID") ? kv["NetID"] : (kv.count("netID") ? kv["netID"] : "0"));
            p.userid = safeInt(kv.count("UserID") ? kv["UserID"] : "0");
            p.pos_x = safeFloat(kv.count("posX") ? kv["posX"] : "0");
            p.pos_y = safeFloat(kv.count("posY") ? kv["posY"] : "0");
            p.size_x = safeFloat(kv.count("sizeX") ? kv["sizeX"] : "0");
            p.size_y = safeFloat(kv.count("sizeY") ? kv["sizeY"] : "0");
            p.world = kv.count("world") ? kv["world"] : "";
            p.flags = safeInt(kv.count("flags") ? kv["flags"] : "0");
            p.flags2 = safeInt(kv.count("flags2") ? kv["flags2"] : "0");

            debugLog("[SPAWN] name=" + p.name + " world=" + p.world +
                " netid=" + std::to_string(p.netid));

            bool found = false;
            for (auto& existing : players) {
                if (existing.netid == p.netid) {
                    existing = p;
                    found = true;
                    break;
                }
            }
            if (!found) players.push_back(p);

            // The first spawn we receive (localPlayer.netid == -1) is always
            // the local player — populate localPlayer so GetLocal works.
            // gems/world are not part of spawn records — keep whatever
            // OnSetBux / log parsing already collected or they reset to 0.
            if (localPlayer.netid == -1 && p.netid >= 0) {
                int keepGems = localPlayer.gems;
                std::string keepWorld = localPlayer.world;
                localPlayer = p;
                localPlayer.gems = keepGems;
                if (!keepWorld.empty()) localPlayer.world = keepWorld;
                debugLog("[SPAWN] Set localPlayer: name=" + p.name +
                    " netid=" + std::to_string(p.netid));
            }
            // If we already have a localPlayer and this spawn matches its netid,
            // update it too (respawn, teleport, etc.)
            else if (p.netid == localPlayer.netid) {
                int keepGems = localPlayer.gems;
                std::string keepWorld = localPlayer.world;
                localPlayer = p;
                localPlayer.gems = keepGems;
                if (!keepWorld.empty()) localPlayer.world = keepWorld;
            }
            // Same player respawning after a warp gets a NEW netid —
            // refresh by name or walk packets would carry the stale id.
            else if (p.netid >= 0 && !p.name.empty() && p.name == localPlayer.name) {
                debugLog("[SPAWN] refreshed localPlayer netid=" +
                    std::to_string(localPlayer.netid) + " -> " + std::to_string(p.netid));
                localPlayer.netid = p.netid;
                localPlayer.pos_x = p.pos_x; localPlayer.pos_y = p.pos_y;
                localPlayer.tile_x = p.tile_x; localPlayer.tile_y = p.tile_y;
            }
        }
        return;
    }

    // This client sends varlist messages as first-line names
    // (OnSetBux\n<amount>, OnGemsCountChange\n<amount>, OnDialogRequest\n...)
    // with no action| key — handle them here and forward to Lua.
    if (action == "on_varlist" ||
        (incoming && action.empty() && kv.count("_0"))) {
        PacketEvent ev;
        ev.type = "OnVarlist";
        ev.text = text;
        std::string msg = kv.count("msg") ? kv["msg"] : kv["_0"];
        if (incoming && (msg == "OnSetBux" || msg == "OnGemsCountChange" ||
                         msg.find("SetBux") != std::string::npos)) {
            int g = -1;
            if (kv.count("_1")) g = safeInt(kv["_1"]);
            else if (kv.count("1")) g = safeInt(kv["1"]);
            else if (kv.count("gems")) g = safeInt(kv["gems"]);
            if (g >= 0) {
                std::lock_guard<std::mutex> lock(mtx);
                localPlayer.gems = g;
                debugLog("[GEMS] " + msg + " -> " + std::to_string(g));
            }
        }
        // pushEvent locks mtx itself — must be called OUTSIDE the lock
        // (calling it while holding mtx = self-deadlock = game freeze)
        pushEvent(ev);
        return;
    }

    if (action == "set_field_init" || action == "set_field_update") {
        std::string fieldType = kv.count("type") ? kv["type"] : "?";
        std::string fieldValue = kv.count("value") ? kv["value"] : "?";
        debugLog("[FIELD] type=" + fieldType + " value=" + fieldValue);
        std::lock_guard<std::mutex> lock(mtx);
        if (kv.count("type")) {
            std::string ft = kv["type"];
            if (ft == "gems" && kv.count("value")) localPlayer.gems = safeInt(kv["value"]);
            else if (ft == "world" && kv.count("value")) localPlayer.world = kv["value"];
            else if (ft == "name" && kv.count("value")) localPlayer.name = kv["value"];
            else if (ft == "country" && kv.count("value")) localPlayer.country = kv["value"];
            else if (ft == "x" && kv.count("value")) localPlayer.pos_x = safeFloat(kv["value"]);
            else if (ft == "y" && kv.count("value")) localPlayer.pos_y = safeFloat(kv["value"]);
            else if (ft == "modx" && kv.count("value")) localPlayer.pos_x = safeFloat(kv["value"]);
            else if (ft == "mody" && kv.count("value")) localPlayer.pos_y = safeFloat(kv["value"]);
            else if (ft == "sizeX" && kv.count("value")) localPlayer.size_x = safeFloat(kv["value"]);
            else if (ft == "sizeY" && kv.count("value")) localPlayer.size_y = safeFloat(kv["value"]);
            else if (ft == "tileX" && kv.count("value")) localPlayer.tile_x = safeInt(kv["value"]);
            else if (ft == "tileY" && kv.count("value")) localPlayer.tile_y = safeInt(kv["value"]);
        }
        if (kv.count("world_name")) localPlayer.world = kv["world_name"];
        if (kv.count("width")) world_size_x = safeInt(kv["width"]);
        if (kv.count("height")) world_size_y = safeInt(kv["height"]);
        return;
    }

    if (action == "on_requestWorldSelectMenu" || action == "on_killed" || action == "on_disconnect") {
        std::lock_guard<std::mutex> lock(mtx);
        players.clear();
        localPlayer = PlayerData();
        return;
    }

    if (action == "on_chat_message" || action == "on_console_message") {
        PacketEvent ev;
        ev.type = "OnVarlist";
        ev.text = text;
        pushEvent(ev);
        return;
    }

    if (action.find("on_") == 0 || action.find("action|") == 0) {
        PacketEvent ev;
        ev.type = incoming ? "OnVarlist" : "OnPacket";
        ev.text = text;
        pushEvent(ev);
        return;
    }

    if (incoming && action == "log" && kv.count("msg") && !kv["msg"].empty()) {
        PacketEvent ev;
        ev.type = "OnVarlist";
        ev.text = "OnConsoleMessage\n" + kv["msg"];
        pushEvent(ev);
        return;
    }

    if (incoming) {
        PacketEvent ev;
        ev.type = "OnVarlist";
        ev.text = text;
        pushEvent(ev);
    }
}

void GameState::parseIncoming(const char* data, int len) {
    if (len < 4) return;

    uint32_t header = *(uint32_t*)data;
    int pktType = header & 0xFF;

    if (pktType == 4) {
        std::string text(data + 4, len - 4);
        if (text.size() > 2) {
            parseTextPacket(text, true);
        }
        return;
    }

    if (pktType == 1 || pktType == 2 || pktType == 3) {
        PacketEvent ev;
        ev.type = "OnRawPacket";
        ev.packet_type = pktType;
        if (len >= 16) ev.netid = *(int*)(data + 8);
        if (len >= 20) ev.item = *(int*)(data + 12);
        if (len >= 28) { ev.pos_x = *(float*)(data + 16); ev.pos_y = *(float*)(data + 20); }
        if (len >= 36) { ev.pos2_x = *(float*)(data + 24); ev.pos2_y = *(float*)(data + 28); }
        if (len >= 24) ev.flags = *(int*)(data + 20);

        static int s_PktRawLogged = 0;
        if (s_PktRawLogged < 40) {
            s_PktRawLogged++;
            char hx[96] = {};
            int hp = 0;
            int showLen = len < 32 ? len : 32;
            for (int i = 0; i < showLen && hp < 90; i++)
                hp += snprintf(hx + hp, 96 - hp, "%02X ", (unsigned char)data[i]);
            consoleLog("[PKT RAW] type=" + std::to_string(pktType) + " len=" +
                       std::to_string(len) + " netid=" + std::to_string(ev.netid) + " " + hx);
        }

        if (pktType == 1) {
            std::lock_guard<std::mutex> lock(mtx);
            for (auto& p : players) {
                if (p.netid == ev.netid) {
                    p.pos_x = ev.pos_x;
                    p.pos_y = ev.pos_y;
                    p.flags = ev.flags;
                    p.tile_x = (int)(ev.pos_x / 32);
                    p.tile_y = (int)(ev.pos_y / 32);
                    break;
                }
            }
            if (ev.netid == localPlayer.netid || ev.netid == -1) {
                localPlayer.pos_x = ev.pos_x;
                localPlayer.pos_y = ev.pos_y;
                localPlayer.flags = ev.flags;
                localPlayer.tile_x = (int)(ev.pos_x / 32);
                localPlayer.tile_y = (int)(ev.pos_y / 32);
            }
        }

        pushEvent(ev);
        return;
    }
}

// Tank-update payload: newline-separated key|val lines (spawn|, netID|,
// posXY|"x,y", userID|, name|, mstate| ...) read from the game's own
// std::string at [rdx+0x20] inside fn_TankParser. Updates player/local
// state only — no OnVarlist events (tank ticks would flood the queue).
void GameState::parseTankUpdate(const std::string& text) {
    if (text.size() < 4) return;

    // same NUL multi-record split as parseTextPacket — spawn records for
    // several players can share one tank payload
    if (text.find('\0') != std::string::npos) {
        size_t start = 0;
        while (start < text.size()) {
            size_t z = text.find('\0', start);
            std::string rec = (z == std::string::npos)
                ? text.substr(start) : text.substr(start, z - start);
            if (rec.size() >= 4) parseTankUpdate(rec);
            if (z == std::string::npos) break;
            start = z + 1;
        }
        return;
    }

    auto kv = parseTextLines(text);

    bool hasSpawn = kv.count("spawn") > 0;
    std::string name = kv.count("name") ? kv["name"] : "";
    int netid = kv.count("netID") ? safeInt(kv["netID"]) : -999;
    if (!hasSpawn && name.empty() && netid == -999) return;

    PlayerData p;
    p.name = name;
    p.netid = netid;
    p.userid = kv.count("userID") ? safeInt(kv["userID"]) : -1;
    p.country = kv.count("country") ? kv["country"] : "us";
    // bothax NetAvatar extras — tank spawn records carry these as ints
    if (kv.count("mstate")) p.mstate = safeInt(kv["mstate"]) != 0;
    if (kv.count("smstate")) p.smstate = safeInt(kv["smstate"]) != 0;
    if (kv.count("invisible")) p.invisible = safeInt(kv["invisible"]) != 0;
    if (kv.count("posXY")) {
        float x = 0, y = 0;
        const std::string& v = kv["posXY"];
        // observed format: "x|y" pipe-separated (e.g. "0|6336" = px);
        // comma form kept as fallback for other dialects
        if (sscanf_s(v.c_str(), "%f|%f", &x, &y) != 2)
            sscanf_s(v.c_str(), "%f,%f", &x, &y);
        p.pos_x = x;
        p.pos_y = y;
    }
    p.tile_x = (int)(p.pos_x / 32);
    p.tile_y = (int)(p.pos_y / 32);

    static int s_TankParsed = 0;
    if (s_TankParsed < 20) {
        s_TankParsed++;
        debugLog("[TANKUP] netid=" + std::to_string(netid) + " spawn=" +
                 std::to_string(hasSpawn) + " name=" + name + " pos=" +
                 std::to_string(p.pos_x) + "," + std::to_string(p.pos_y));
    }

    std::lock_guard<std::mutex> lock(mtx);
    if (hasSpawn || !name.empty()) {
        bool found = false;
        for (auto& existing : players) {
            if (netid != -999 && existing.netid == netid) {
                if (!name.empty()) existing.name = name;
                if (p.pos_x != 0 || p.pos_y != 0) {
                    existing.pos_x = p.pos_x; existing.pos_y = p.pos_y;
                    existing.tile_x = p.tile_x; existing.tile_y = p.tile_y;
                }
                found = true;
                break;
            }
        }
        if (!found && netid != -999) players.push_back(p);
        if (hasSpawn) {
            if (localPlayer.netid == -1 && netid >= 0) {
                int keepGems = localPlayer.gems;
                std::string keepWorld = localPlayer.world;
                localPlayer = p;
                localPlayer.gems = keepGems;
                if (!keepWorld.empty()) localPlayer.world = keepWorld;
                debugLog("[TANKUP] Set localPlayer netid=" + std::to_string(netid));
            } else if (netid >= 0 && !name.empty() && name == localPlayer.name) {
                debugLog("[TANKUP] refreshed localPlayer netid=" +
                         std::to_string(localPlayer.netid) + " -> " + std::to_string(netid));
                localPlayer.netid = netid;
                if (p.pos_x != 0 || p.pos_y != 0) {
                    localPlayer.pos_x = p.pos_x; localPlayer.pos_y = p.pos_y;
                    localPlayer.tile_x = p.tile_x; localPlayer.tile_y = p.tile_y;
                }
            } else if (netid == localPlayer.netid) {
                localPlayer.pos_x = p.pos_x; localPlayer.pos_y = p.pos_y;
                localPlayer.tile_x = p.tile_x; localPlayer.tile_y = p.tile_y;
            }
        } else if (netid == localPlayer.netid) {
            localPlayer.pos_x = p.pos_x; localPlayer.pos_y = p.pos_y;
            localPlayer.tile_x = p.tile_x; localPlayer.tile_y = p.tile_y;
        }
    } else if (netid != -999) {
        for (auto& existing : players) {
            if (existing.netid == netid) {
                existing.pos_x = p.pos_x; existing.pos_y = p.pos_y;
                existing.tile_x = p.tile_x; existing.tile_y = p.tile_y;
                break;
            }
        }
        if (netid == localPlayer.netid) {
            localPlayer.pos_x = p.pos_x; localPlayer.pos_y = p.pos_y;
            localPlayer.tile_x = p.tile_x; localPlayer.tile_y = p.tile_y;
        }
    }
}

bool GameState::interceptCommand(const char* data, int len) {
    if (!data || len < 5 || len > 65536) return false;

    auto strip = [](std::string& t) {
        while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
    };
    auto printable = [](const std::string& t) {
        if (t.empty() || t.size() > 512) return false;
        for (unsigned char c : t)
            if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c > 0x7E) return false;
        return true;
    };
    // Dispatch OnCommand; suppress the outbound packet ONLY when a Lua
    // RegisterCommand handler exists for the name (registered commands are
    // purely local — server never sees them; everything else with a leading
    // '/' passes through so GT's built-in commands still work).
    auto accept = [&](const std::string& cmdRaw) -> bool {
        if (cmdRaw.size() < 2) return false;
        size_t sp = cmdRaw.find(' ');
        std::string name = (sp == std::string::npos)
            ? cmdRaw.substr(1) : cmdRaw.substr(1, sp - 1);
        debugLog("[CMD] intercepted: " + cmdRaw.substr(0, 120));
        PacketEvent ev;
        ev.type = "OnCommand";
        ev.text = cmdRaw;
        pushEvent(ev);
        if (g_luaCommands.count(name)) {
            debugLog("[CMD] suppressed (registered): /" + name);
            return true;
        }
        return false;
    };

    // shape A: framed [hdr u32] + raw "/cmd" text at +4 (type byte must be
    // a text type so float/binary payloads at +4 can't false-positive)
    uint32_t hdr = 0;
    memcpy(&hdr, data, 4);
    int ptype = hdr & 0xFF;
    if ((ptype == 2 || ptype == 4) && len > 4) {
        std::string a(data + 4, len - 4);
        strip(a);
        if (!a.empty() && a[0] == '/' && printable(a)) return accept(a);
    }

    // shape B: unframed "/cmd" at offset 0
    if ((uint8_t)data[0] == '/') {
        std::string b(data, len);
        strip(b);
        if (printable(b)) return accept(b);
    }

    // shape C: GrowPai-style chat wire format "action|input\n|text|/cmd"
    for (int s = 0; s < 2; s++) {
        std::string t = s ? std::string(data, len > 64 ? 64 : len)
                          : std::string(data + 4, len > 4 ? (len > 68 ? 64 : len - 4) : 0);
        size_t p = t.find("|text|");
        if (p != std::string::npos && p + 6 < t.size() && t[p + 6] == '/') {
            std::string cmd = t.substr(p + 6);
            strip(cmd);
            if (printable(cmd)) return accept(cmd);
        }
    }
    return false;
}

bool GameState::parseOutgoing(const char* data, int len) {
    if (len < 4) return true;

    uint32_t header = *(uint32_t*)data;
    int pktType = header & 0xFF;

    // GrowPai SendPacket(type, "action|...") uses type 2 for text; this
    // client's parser historically expected 4 — accept both.
    if (pktType == 4 || pktType == 2) {
        std::string text(data + 4, len - 4);
        if (text.size() > 2) {
            // OnSendPacket dispatch happens at hk_SendPacket (app layer,
            // plaintext) — this socket/TLS layer only sees encrypted bytes.
            parseTextPacket(text, false);
        }
        if (pktType == 4) return true;
    }

    if (pktType == 1 || pktType == 2 || pktType == 3) {
        PacketEvent ev;
        ev.type = "OnPacket";
        ev.packet_type = pktType;
        if (len >= 16) ev.netid = *(int*)(data + 8);
        if (len >= 20) ev.item = *(int*)(data + 12);
        if (len >= 28) { ev.pos_x = *(float*)(data + 16); ev.pos_y = *(float*)(data + 20); }
        // GrowPai-parity: attach payload string for text-ish packets so
        // lua's onPacket(ptype, packet) can pattern-match it.
        if (len > 4 && len < 65536) {
            const char* p = data + 4;
            size_t pl = (size_t)len - 4;
            size_t chk = pl < 16 ? pl : 16;
            bool txt = chk > 0;
            for (size_t i = 0; i < chk; i++) {
                unsigned char c = (unsigned char)p[i];
                if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') { txt = false; break; }
            }
            if (txt) ev.text.assign(p, pl);
        }
        {
            static int s_PktOutLogged = 0;
            if (s_PktOutLogged < 60) {
                s_PktOutLogged++;
                void* frames[4] = {};
                USHORT nf = CaptureStackBackTrace(0, 4, frames, NULL);
                char from[96] = {};
                int fp = 0;
                for (USHORT i = 1; i < nf && i < 4 && fp < 88; i++) {
                    fp += snprintf(from + fp, 96 - fp, " %p", frames[i]);
                }
                char hex[160] = {};
                int hp = 0;
                int show = len < 36 ? len : 36;
                for (int i = 0; i < show && hp < 150; i++)
                    hp += snprintf(hex + hp, sizeof(hex) - hp, " %02X",
                                   (unsigned char)data[i]);
                debugLog("[PKT OUT RAW] type=" + std::to_string(pktType) +
                         " len=" + std::to_string(len) + " head:" + hex +
                         " from:" + from);
            }
        }
        pushEvent(ev);
    }
    return true;
}

std::atomic<bool> g_OnTankPacket{false};

void GameState::pushEvent(const PacketEvent& ev) {
    std::lock_guard<std::mutex> lock(mtx);
    events.push(ev);
    if (events.size() > 500) {
        // burst guard: drop the OLDEST half — never wipe the whole queue
        // (tank-event bursts must not destroy pending OnVarlist events)
        size_t drop = events.size() / 2;
        for (size_t i = 0; i < drop && !events.empty(); i++) events.pop();
    }
}

bool GameState::popEvent(PacketEvent& ev) {
    std::lock_guard<std::mutex> lock(mtx);
    if (events.empty()) return false;
    ev = events.front();
    events.pop();
    return true;
}

// ── wglSwapBuffers hook ──────────────────────────────────────────────
BOOL WINAPI hk_wglSwapBuffers(HDC hdc) {
    if (!g_Initialized) {
        g_GameHWND = WindowFromDC(hdc);

        if (g_GameHWND) {
            oWndProc = (WNDPROC)SetWindowLongPtrW(g_GameHWND, GWLP_WNDPROC, (LONG_PTR)hkWndProc);
        }

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.IniFilename = nullptr;
        io.SetClipboardTextFn = ClipSetText;
        io.GetClipboardTextFn = ClipGetText;

        ImGui::StyleColorsDark();
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 6.0f;
        style.FrameRounding = 4.0f;
        style.Alpha = 0.95f;
        style.WindowBorderSize = 1.0f;

        ImGui_ImplWin32_Init(g_GameHWND);
        ImGui_ImplOpenGL3_Init("#version 330");

        g_executor = new LuaExecutor();
        g_Initialized = true;
        consoleLog("[INFO] EpsHax initialized inside Growtopia");
    }

    // Poll F1 via GetAsyncKeyState instead of global keyboard hook.
    // SetWindowsHookExW(WH_KEYBOARD_LL) is detected by Themida/VMProtect
    // and causes ACCESS_VIOLATION when the user presses any key.
    {
        bool f1Down = (GetAsyncKeyState(VK_F1) & 0x8000) != 0;
        if (f1Down && !g_F1WasDown) {
            g_MenuOpen = !g_MenuOpen;
        }
        g_F1WasDown = f1Down;
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (g_MenuOpen) {
        ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(700, 500), ImGuiCond_FirstUseEver);
        ImGui::Begin("EpsHax  |  F1 to toggle##executor", &g_MenuOpen,
            ImGuiWindowFlags_NoCollapse);

        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("Tools")) {
                ImGui::MenuItem("Console", nullptr, &showConsole);
                ImGui::MenuItem("Debug Output", nullptr, &showDebug);
                ImGui::MenuItem("Settings", nullptr, &showSettings);
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        bool running = g_executor->isRunning();

        ImGui::PushStyleColor(ImGuiCol_Button, running
            ? ImVec4(0.6f, 0.2f, 0.2f, 1.0f)
            : ImVec4(0.2f, 0.6f, 0.2f, 1.0f));
        if (ImGui::Button(running ? "Running..." : "Execute", ImVec2(100, 25)) && !running) {
            { std::lock_guard<std::mutex> l(g_consoleMutex); g_consoleLogs.clear(); }
            { std::lock_guard<std::mutex> l(g_debugMutex); g_debugLogs.clear(); }
            std::string script(scriptBuf);
            debugLog("[SYSTEM] Executing script...");
            LuaExecutor* exec = g_executor;
            std::thread t([exec, script]() { exec->execute(script); });
            t.detach();
        }
        ImGui::PopStyleColor();
        ImGui::SameLine();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
        if (ImGui::Button("Stop", ImVec2(70, 25))) {
            g_executor->stop();
            debugLog("[SYSTEM] Script stopped.");
        }
        ImGui::PopStyleColor();
        ImGui::SameLine();

        if (ImGui::Button("Clear")) {
            std::lock_guard<std::mutex> l(g_consoleMutex);
            std::lock_guard<std::mutex> l2(g_debugMutex);
            g_consoleLogs.clear();
            g_debugLogs.clear();
        }
        ImGui::SameLine();
        ImGui::Checkbox("Auto-scroll", &autoScroll);
        ImGui::SameLine(0, 20);
        ImGui::TextColored(running ? ImVec4(0,1,0,1) : ImVec4(0.5f,0.5f,0.5f,1),
            running ? "RUNNING" : "IDLE");

        ImGui::Separator();

        float bottomH = 0;
        if (showConsole) bottomH += 120;
        if (showDebug) bottomH += 100;
        if (showSettings) bottomH += 80;
        float editorH = ImGui::GetContentRegionAvail().y - bottomH;
        if (editorH < 80) editorH = 80;

        ImGui::BeginChild("Editor", ImVec2(0, editorH), true);
        ImGui::InputTextMultiline("##script", scriptBuf, sizeof(scriptBuf),
            ImVec2(-1, -1), ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_NoHorizontalScroll);
        ImGui::EndChild();

        if (showSettings) {
            ImGui::BeginChild("Settings", ImVec2(0, 95), true);
            ImGui::Text("Tick Interval: %.1fs", g_TickInterval);
            ImGui::SameLine();
            if (ImGui::SliderFloat("##tick", &g_TickInterval, 0.1f, 5.0f, "%.1fs")) {
                if (g_executor) g_executor->setTickInterval(g_TickInterval);
            }
            ImGui::Text("Debug Filters");
            ImGui::Columns(3, nullptr, false);
            ImGui::Checkbox("Packets", &debugPackets);
            ImGui::Checkbox("Callbacks", &debugCallbacks);
            ImGui::Checkbox("Timers", &debugTimer);
            ImGui::NextColumn();
            ImGui::Checkbox("Pathfinding", &debugPathfinding);
            ImGui::Checkbox("Inventory", &debugInventory);
            ImGui::Checkbox("Players", &debugPlayers);
            ImGui::NextColumn();
            if (ImGui::Button("Clear Debug", ImVec2(-1, 0))) {
                std::lock_guard<std::mutex> l(g_debugMutex);
                g_debugLogs.clear();
            }
            ImGui::Columns(1);
            ImGui::EndChild();
        }

        if (showDebug) {
            ImGui::BeginChild("DebugOutput", ImVec2(0, 95), true);
            {
                std::lock_guard<std::mutex> lock(g_debugMutex);
                int start = (int)g_debugLogs.size() - 15;
                if (start < 0) start = 0;
                for (int i = start; i < (int)g_debugLogs.size(); i++) {
                    const auto& e = g_debugLogs[i];
                    bool show = true;
                    if (!debugPackets && e.message.find("[PACKET]") != std::string::npos) show = false;
                    if (!debugCallbacks && e.message.find("[CALLBACK]") != std::string::npos) show = false;
                    if (!debugTimer && e.message.find("[TIMER]") != std::string::npos) show = false;
                    if (!debugPathfinding && e.message.find("[PATH]") != std::string::npos) show = false;
                    if (!debugInventory && e.message.find("[INV]") != std::string::npos) show = false;
                    if (!debugPlayers && e.message.find("[PLAYER]") != std::string::npos) show = false;
                    if (show) ImGui::TextUnformatted(e.message.c_str());
                }
            }
            ImGui::EndChild();
        }

        if (showConsole) {
            ImGui::BeginChild("Console", ImVec2(0, 115), true);
            {
                std::lock_guard<std::mutex> lock(g_consoleMutex);
                int start = (int)g_consoleLogs.size() - 15;
                if (start < 0) start = 0;
                for (int i = start; i < (int)g_consoleLogs.size(); i++) {
                    const auto& e = g_consoleLogs[i];
                    if (e.message.find("[ERROR]") != std::string::npos)
                        ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "%s", e.message.c_str());
                    else if (e.message.find("[INFO]") != std::string::npos)
                        ImGui::TextColored(ImVec4(0.3f, 0.8f, 1, 1), "%s", e.message.c_str());
                    else
                        ImGui::TextUnformatted(e.message.c_str());
                }
            }
            if (autoScroll) ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();
        }

        ImGui::End();
    }

    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    // Tick executor from render thread
    if (g_executor && g_executor->isRunning()) {
        static float lastTick = 0;
        float dt = g_currentTime - lastTick;
        if (dt >= g_TickInterval) {
            lastTick = g_currentTime;
            g_executor->tick(dt);
        }
    }

    return o_wglSwapBuffers(hdc);
}
