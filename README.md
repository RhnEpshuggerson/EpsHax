# EpsHax

Windows Lua executor for Growtopia, built for script compatibility and
stability. Targets both **Growtopia.exe** (retail) and
**CreativeGrowtopia.exe** (ASLR build) — the game build is detected at
inject time and the correct memory layout is used automatically.

Script ecosystems supported:

- **bothax API** — 68/68 parity on the bothax test suite (see `BOTHAX_RESULTS.md`)
- **GrowPai** legacy spellings (`onvarlist`, `ontankpacket`, `AddHook` …)
- Plain EpsHax/Growtopia-style scripts (`AddCallback`, `SendPacket`, `FindPath` …)

## Highlights

- **Dual-build support** — full layout coverage for both game builds:
  world/tile map (per-build stride and field offsets), world objects,
  player state, item database up to id 17217+
- **Packet pipeline** — inbound text/tank/varlist interception, sync
  blocking hooks (`OnVariant` / `OnSendPacket` / `OnSendPacketRaw`),
  outbound `SendPacket` detour, `SendPacketRaw` movement/tank payloads
- **Live state caches** — `GetLocal` (name/netid/pos), `GetPlayers`,
  `GetWorld`, `GetTile(s)` with raw `SetTileFlags` writes,
  `GetObjects`/`GetDroppedItems`, realtime gem counter (client wallet
  at ctx+0x2D0 with packet fallback)
- **Pathfinding** — `FindPath` coroutine walk that yields until arrival
  (~20 s timeout) and emits real state packets
- **Scripting** — coroutines, `Sleep` (yield-based), `RunThread`,
  `timer.Create/Destroy/Update`, `RegisterCommand`, delayed calls,
  HTTP `MakeRequest`, `SendWebhook` (async), crypto/hash helpers
- **Stability** — pid-tagged append-only log with 32 MB rotation (GT and
  CG share one log without clobbering each other), bounded log spam,
  crash text log + minidump, contention-proof hook dispatch (events are
  queued instead of blocking the game thread on `g_LuaMtx`)
- **Watchdog** — process supervision for both games, login verification,
  in-place recovery + suite restore, 120 s unresponsive-window detection
  with hang dumps (keeps newest 5)
- **GUI launcher** — `EpsHaxLauncher` (Win32 GUI, app icon, script
  picker, loader-based injection), Discord rich presence
- **Tests** — `ApiTest` host suite **54/54 green**

## Components

| Component | Purpose |
|-----------|---------|
| `EpsHax*.dll` | Injected executor (Lua VM + hooks). Name ladders per build: `EpsHax10.dll` → `EpsHax9.dll` → … (newest built wins) |
| `EpsHaxLauncher` | GUI launcher: picks newest DLL, injects, runs scripts |
| `loader` | CLI injector (`-q` quiet / `-e` / `-p`, spawns a fresh game by default) |
| `watchdog.py` | Keeps both games logged in; hang detector + crash recovery |
| `inject_run.py` | Headless: inject (if needed) + poke+run a script in the live game |
| `gt_launch.py` | Game launch helper (correct cwd for log verification) |
| `ApiTest` | Host test suite — runs the Lua API without a game (54 tests) |

## API

### Callbacks (`AddCallback(type, fn)`) and hooks (`AddHook(hook, id, fn)`)

| Event | Fires on |
|-------|----------|
| `OnVarlist` | incoming variant/text packet (also `onvarlist`, `onconsolemessage`) |
| `OnPacket` | incoming/outgoing text-ish packet (`type`, `text`) |
| `OnTankPacket` | tank update packet (`OnProcessTankUpdate` alias) |
| `OnUpdate` | per-tick while script running |
| `OnSendPacket` / `OnSendPacketRaw` | outgoing packets — **sync, can block** (`return true`) |
| `OnVariant` | incoming variant — **sync, can block** |
| `OnCommand` | registered slash command |
| `OnDraw` / `OnInput` | render tick / input |
| `OnWorldTouch` | world touch events |

Sync hooks are dispatched on the packet thread with a try-lock: if the
script is busy, the event is queued and replayed on the next tick
instead of freezing the game.

### Functions

**Packets** — `SendPacket`, `SendPacketRaw`, `SendPacketRawClient`,
`SendVarlist`, `SendVariantList`, `MakeRequest`, `RequestJoinWorld`,
`EditToggle`, `Encrypt`/`LoadEncrypt`/`EncryptFile`/`LoadEncryptedFile`
(XOR+base64 roundtrip — not byte-compatible with the closed-source
bothax cipher)

**State** — `GetLocal`, `GetLocalObject`, `GetPlayers`, `GetPlayer`,
`GetPlayerInfo`, `GetPlayerList`, `GetWorld`, `GetTile`, `GetTiles`,
`GetObjects`, `GetObjectList`, `GetDroppedItems`, `GetInventory`,
`GetItemCount`, `GetNPC`, `GetNPCList`, `GetPlayerItems`,
`GetAccesslist`, `GetGhost`, `GetCamera`, `GetClient`, `GetPing`

**Items** — `GetItemInfo`, `GetItemByIDSafe`, `GetItemByName`,
`GetItemInfoList`, `GetItemsByPartialName`, `SetItemSelected`

**World** — `FindPath`, `PathFind`, `CheckPath`, `IsSolid`,
`SetTileFlags` (raw flag-word write), `RunDelayed`

**Script** — `log`, `LogToConsole`, `Sleep`, `RunThread`,
`AddCallback`, `RemoveCallback`, `RemoveCallbacks`, `AddHook`,
`RemoveHook`, `RemoveHooks`, `RegisterCommand`, `timer.Create`,
`timer.Destroy`, `timer.Update`, `MessageBox`, `ChangeValue`,
`Hash32`, `Hash64`, `SendWebhook`

### Known gaps

- `GetInventory` on CreativeGrowtopia returns an empty table — the
  inventory container location is not yet mapped (retail build works).
- `ChangeValue` stores the setting; EpsHax has no matching feature to
  apply it to yet (per bothax spec: no error, no return value).

## Build (Windows)

Prerequisites: CMake 3.20+, Visual Studio 2019/2022 (C++17), Git.

```bash
# 1. ImGui into libs/
git clone https://github.com/ocornut/imgui.git libs/imgui

# 2. configure + build (from this directory)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
```

Outputs in `build\Debug\`:

- `EpsHax10.dll` — the injected DLL (`OUTPUT_NAME` ladders up when a
  running game file-locks the previous name; see `inject_run.py`
  `_candidates` and `src/launcher.cpp` `PickDll`)
- `EpsHaxLauncher.exe` — GUI launcher
- `ApiTest.exe` — host test suite

## Test

```bash
./build/Debug/ApiTest.exe          # expect: === 54 passed, 0 failed ===
grep -a BOTHAXTEST "package-scanner-output/Cmd Log/log.txt"   # bothax suite
```

## Tools

```bash
# run a script inside the live game (auto-elevates; injects only if needed)
python inject_run.py my_script.lua [target_exe]

# watchdog (already running as a service-style loop)
pythonw watchdog.py     # stop: create watchdog.stop
```

Logs: `package-scanner-output\Cmd Log\log.txt` (pid-tagged, append-only,
rotates at 32 MB to `log.txt.old`), `watchdog.log`, crash dumps in
`package-scanner-output\`.

## Operational notes

- The DLL has **no unload path**: upgrades take effect the next time the
  game restarts naturally. Never load two EpsHax copies into one process.
- Only ever kill single PIDs when restarting manually — never
  `taskkill /IM` while scripts are farming.
