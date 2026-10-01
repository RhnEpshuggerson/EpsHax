# EpsHax bothax test results — 2026-10-01

## Final: 68/68 passed, in-game, live server (AFKWINDY)

- Host test: `./build/Debug/ApiTest.exe` → 54/54
- In-game: `test_bothax.lua` poked into live Growtopia (inject-at-menu → login flow)
  → `FINAL RESULT 68/68 passed` (MakeRequest skipped: WinHTTP 12175, not counted)
- DLL: `build\Debug\EpsHax6.dll` (CMake OUTPUT_NAME EpsHax6)
- Log: `package-scanner-output\Cmd Log\log.txt` (grep -a; truncated on each EpsHax boot)

## Bugs found & fixed this session

1. **Anti-tamper bypass** — GT hooks `ntdisk!NtProtectVirtualMemory` so our .text
   writes returned err=5. Fixed in `src/epshook.cpp`: parse SSN from on-disk ntdll,
   build a raw `syscall` stub in RWX memory, use it for all hook writes.
   All 6 GT hooks install live (PTUP/SendPacket/LoadFromMem/TextDispatch/TANKPARSER…).
2. **Debug-CRT iterator wedge** — `startThread()` push_back during tick's range-for
   resume loop reallocated `threads`, invalidating the iterator → assert dialog froze
   the tick thread → `g_LuaMtx` held forever → scripts stopped running.
   Fixed in `src/lua_api.cpp` / `src/lua_bothax.cpp`: index-based loops + ref snapshots.
3. **OnSendPacket/OnSendPacketRaw dispatch layer** — hooks were dispatched from the
   socket/TLS layers, which only see *encrypted* bytes, so text matches never hit.
   Moved dispatch into `hk_SendPacket` (`src/dllmain.cpp`), the app-layer plaintext
   chokepoint; removed the encrypted-layer calls from `parseOutgoing`.
   Text-ish payloads (type 2/4 + printable) → OnSendPacket; everything else
   (GUP movement/type-10…) → OnSendPacketRaw. `return true` suppresses the send
   (verified: `[SENDPKT] Lua hook blocked type=4`).
4. **OnVariant visibility** — incoming text variants dispatch on the recv thread;
   the test window was shorter than the server's ~7-10 s beep cadence. Test now
   polls up to 20 s. Added rate-limited `[DSPVAR]` diagnostics in `dispatchVariant`.

## Known limitations

- `MakeRequest` fails in-process (WinHTTP ERROR_CANNOT_CONNECT 12175) → test SKIPs.
- `RequestJoinWorld` sends `action|join_request\nname|WORLD\ninvitedWorld|0` (type 3)
  but this GTPS ignores it — no rejoin occurs (the binary contains no
  `join_request` string; the game's own join mechanism is different).
  With the inject-at-menu flow this does not matter: state is fully populated
  on login (GetLocal.name/world/netid, tiles, inventory… all PASS).

## Repro flow

```
kill Growtopia (NOT CreativeGrowtopia — it locks EpsHax.dll)
cmake --build build --config Debug --target EpsHax && ./build/Debug/ApiTest.exe
run_elev "python gt_launch.py"
run_elev "python inject_run.py probe_sleep.lua Growtopia.exe"   # inject at menu
run_elev "python click_play.py"                                 # Play Online
sleep 30                                                        # LoadFromMem + sync
run_elev "python inject_run.py <script> Growtopia.exe"          # poke script
grep -a BOTHAXTEST "package-scanner-output/Cmd Log/log.txt"
```
