#pragma once
#include "hook.h"
#include <string>

// Lazy, thread-safe loader for data/items.tsv (17678 entries exported from
// %LOCALAPPDATA%\Growtopia\cache\items.dat — name, filename, rarity, breakhit,
// growtime, type, coltype, clothingtype, visualstyle, texturex/y, flags).
// Fills GameState::itemDatabase in place; safe to call from any Lua function.
namespace itemdb {
    void ensureLoaded();
    // true once the TSV (or a previous failed attempt) finished
    bool loaded();
    const ItemInfo* get(int id);
    const ItemInfo* byName(const std::string& name);      // case-insensitive exact
    std::vector<const ItemInfo*> partial(const std::string& needle); // case-insensitive contains
}
