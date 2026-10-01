#include "itemdb.h"
#include "lua_api.h"
#include <fstream>
#include <sstream>
#include <mutex>
#include <vector>
#include <atomic>

namespace itemdb {

static std::once_flag g_Flag;
static bool g_Ok = false;
static std::vector<ItemInfo> g_Items;       // stable-address copy for index lookups
static std::vector<int> g_IdToIdx;          // id -> index into g_Items

static const char* kPath =
    "C:\\Users\\LENOVO\\Documents\\groetopia\\cv dl script\\coems_executor\\data\\items.tsv";

static void load() {
    std::ifstream f(kPath);
    if (!f.is_open()) {
        consoleLog("[ITEMDB] cannot open " + std::string(kPath));
        g_Ok = false;
        return;
    }
    std::vector<ItemInfo> items;
    items.reserve(18000);
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // id \t name \t filename \t rarity \t breakhit \t growtime \t type \t
        // coltype \t clothingtype \t visualstyle \t texturex \t texturey \t flags
        int col = 0;
        ItemInfo it;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '\t')) {
            switch (col) {
                case 0: it.id = atoi(cell.c_str()); break;
                case 1: it.name = cell; break;
                case 2: it.filename = cell; break;
                case 3: it.rarity = atoi(cell.c_str()); break;
                case 4: it.breakhit = atoi(cell.c_str()); break;
                case 5: it.growtime = atoi(cell.c_str()); it.growth = it.growtime; break;
                case 6: it.item_type = atoi(cell.c_str()); break;
                case 7: it.coltype = atoi(cell.c_str()); break;
                case 8: it.clothingtype = atoi(cell.c_str()); break;
                case 9: it.visualstyle = atoi(cell.c_str()); break;
                case 10: it.texturex = atoi(cell.c_str()); break;
                case 11: it.texturey = atoi(cell.c_str()); break;
                case 12: it.flags = atoi(cell.c_str()); break;
            }
            col++;
        }
        if (col < 13 || it.name.empty()) continue;
        it.size = 0; // capacity unknown from TSV; bothax ItemInfo has no size
        items.push_back(it);
    }
    int maxId = 0;
    for (auto& it : items) if (it.id > maxId) maxId = it.id;
    g_IdToIdx.assign(maxId + 1, -1);
    auto& gs = GameState::instance();
    {
        std::lock_guard<std::mutex> lk(gs.mtx);
        for (size_t i = 0; i < items.size(); i++) {
            ItemInfo& it = items[i];
            if (it.id >= 0 && it.id <= maxId) g_IdToIdx[it.id] = (int)i;
            gs.itemDatabase[it.id] = it;
        }
    }
    g_Items = std::move(items);
    g_Ok = true;
    consoleLog("[ITEMDB] loaded " + std::to_string(g_Items.size()) + " items from items.dat export");
}

void ensureLoaded() { std::call_once(g_Flag, load); }
bool loaded() { return g_Ok; }

const ItemInfo* get(int id) {
    ensureLoaded();
    if (!g_Ok || id < 0 || id >= (int)g_IdToIdx.size()) return nullptr;
    int idx = g_IdToIdx[id];
    if (idx < 0) return nullptr;
    return &g_Items[idx];
}

const ItemInfo* byName(const std::string& name) {
    ensureLoaded();
    if (!g_Ok) return nullptr;
    for (auto& it : g_Items)
        if (_stricmp(it.name.c_str(), name.c_str()) == 0) return &it;
    return nullptr;
}

std::vector<const ItemInfo*> partial(const std::string& needle) {
    ensureLoaded();
    std::vector<const ItemInfo*> out;
    if (!g_Ok || needle.empty()) return out;
    std::string n = needle;
    for (auto& c : n) c = (char)tolower((unsigned char)c);
    for (auto& it : g_Items) {
        std::string nm = it.name;
        for (auto& c : nm) c = (char)tolower((unsigned char)c);
        if (nm.find(n) != std::string::npos) {
            out.push_back(&it);
            if (out.size() >= 500) break;
        }
    }
    return out;
}

} // namespace itemdb
