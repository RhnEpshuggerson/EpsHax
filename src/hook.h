#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <queue>
#include <map>
#include <unordered_set>

// Names registered via Lua RegisterCommand — interceptCommand only
// suppresses outbound slash-packets whose command name is in this set
// (anything else starting with '/' passes to the server untouched).
extern std::unordered_set<std::string> g_luaCommands;

typedef BOOL(WINAPI* wglSwapBuffers_t)(HDC hdc);
extern wglSwapBuffers_t o_wglSwapBuffers;
BOOL WINAPI hk_wglSwapBuffers(HDC hdc);

extern bool g_Initialized;
extern HWND g_GameHWND;
extern bool g_MenuOpen;
extern bool g_SocketHooksInstalled;
void TryInstallSocketHooks();

struct PlayerData {
    std::string name;
    std::string world;
    std::string country;
    float pos_x = 0, pos_y = 0;
    int tile_x = 0, tile_y = 0;
    float size_x = 0, size_y = 0;
    int netid = -1;
    int userid = 0;
    int gems = 0;
    int item = -1;
    bool facing_left = false;
    int flags = 0, flags2 = 0;
    // bothax NetAvatar extras (tank kv: mstate|, smstate|, invisible|)
    bool invisible = false, mstate = false, smstate = false;
};

struct TileData {
    int fg = 0, bg = 0;
    int pos_x = 0, pos_y = 0;
    int flags = 0;
    int extra = 0;   // tile+0xC0 wire word (diagnosis)
    bool water = false, fire = false, ready = false;
};

struct InventoryItem {
    int id = 0;
    int count = 0;
    int flags = 0;   // PlayerItems entry byte @+0x13
};

// bothax ClientNPC — tracked from tank type-34 events
struct NPCData {
    int id = 0;
    int type = 0;
    float pos_x = 0, pos_y = 0;
    float target_x = 0, target_y = 0;
};

// bothax ItemInfo — filled from data/items.tsv (parsed from items.dat)
struct ItemInfo {
    std::string name = "Unknown";
    std::string filename;
    int id = 0;
    int item_type = 0;
    int growth = 0;       // legacy key (growtime)
    int rarity = 0;
    int size = 0;
    int breakhit = 0;
    int growtime = 0;
    int coltype = 0;
    int clothingtype = 0;
    int visualstyle = 0;
    int texturex = 0;
    int texturey = 0;
    int flags = 0;        // item property bits (items.dat Properties)
};

struct WorldObject {
    int id = 0;
    int oid = 0;
    float pos_x = 0, pos_y = 0;
    int count = 0;
    int flags = 0;
};

struct GamePacket {
    int type = 0;
    int objtype = 0;
    int count1 = 0;
    int count2 = 0;
    int netid = 0;
    int item = 0;
    int flags = 0;
    float float1 = 0;
    int int_data = 0;
    float pos_x = 0, pos_y = 0;
    float pos2_x = 0, pos2_y = 0;
    float float2 = 0;
    int int_x = 0, int_y = 0;
};

struct PacketEvent {
    std::string type;
    int packet_type = 0;
    std::string text;
    int int_data = 0;
    int netid = 0;
    float pos_x = 0, pos_y = 0;
    float pos2_x = 0, pos2_y = 0;
    int flags = 0;
    int item = 0;
    float delta_time = 0;
    // tank-packet payload (PlayerMoving +32/+36) — OnTankPacket only
    float xspeed = 0, yspeed = 0;
};

// set when a Lua "OnTankPacket" callback is registered (spy_ptup gate)
#include <atomic>
extern std::atomic<bool> g_OnTankPacket;

class GameState {
public:
    static GameState& instance();

    PlayerData localPlayer;
    std::vector<PlayerData> players;
    std::vector<std::vector<TileData>> tiles;
    std::vector<InventoryItem> inventory;
    std::map<int, ItemInfo> itemDatabase;
    std::vector<WorldObject> objects;
    std::vector<NPCData> npcs;          // bothax GetNPCList
    int world_size_x = 0, world_size_y = 0;
    int ping_ms = 0;
    std::string server_addr;            // bothax GetClient
    int server_port = 0;

    std::mutex mtx;
    std::queue<PacketEvent> events;

    void parseIncoming(const char* data, int len);
    // returns false when a Lua OnSendPacket/OnSendPacketRaw hook returned
    // true — caller must suppress the outbound packet
    bool parseOutgoing(const char* data, int len);
    // Slash-command intercept: true if buf was a "/command" packet that was
    // dispatched to Lua (caller must NOT forward it to the server).
    bool interceptCommand(const char* data, int len);
    void pushEvent(const PacketEvent& ev);
    bool popEvent(PacketEvent& ev);
    void parseTextPacket(const std::string& text, bool incoming);
    void parseTankUpdate(const std::string& text);
};

// lua-side singleton used by hook.cpp (execute button) and the sync
// OnVariant/OnSendPacket/OnSendPacketRaw hook bridge (lua_bothax.cpp)
class LuaExecutor;
extern LuaExecutor* g_executor;

// tile vector base captured by SyncGameCaches — SetTileFlags writes here
// (same-process direct write at tile + idx*0xF0 + 0x52, the word that
// SyncGameCaches reads into TileData::flags)
extern std::atomic<uintptr_t> g_TileBegin;
extern std::atomic<int> g_TileW;
extern std::atomic<int> g_TileH;

// dllmain: pull world size/tiles/objects + inventory out of the live game
// structures (ctx 0x140B2D9D0, world [ctx+0x110], PlayerItems ctx+0x210).
// Safe no-op until the first World::LoadFromMem detour captures the ctx.
void SyncGameCaches(bool log);
