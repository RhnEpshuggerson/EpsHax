#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

namespace scanner {
    bool Install(HMODULE gameModule);
    bool HooksInstalled();

    extern uintptr_t fn_ProcessTankUpdatePacket;
    extern uintptr_t fn_SendPacket;
    extern uintptr_t fn_GetGameLogic;
    extern uintptr_t fn_TextDispatch;
    extern uintptr_t fn_RecvWrapper;
    extern uintptr_t fn_TankParser;
    extern uintptr_t fn_LoadFromMem;
    extern uintptr_t fn_GetCtx;

    void* CallGetGameLogic();
    void CallSendPacket(int type, const char* text);
    // binary-safe variant (embedded NULs) — movement/tank payloads
    void CallSendPacketBin(int type, const void* data, size_t len);

    void ScanRecvWrapper();

    extern uintptr_t g_GameBase;
    extern size_t g_GameImageSize;
}
