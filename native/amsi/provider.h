// Purpose: Declare AMSI provider interfaces and shared native registration contracts.
// Works with: provider.cpp; harness.cpp; probe.cpp
// Used by: the matching native executable or library entry point

#pragma once
#include <windows.h>
#include <amsi.h>

// Not registered by this build or its test harness.
inline constexpr CLSID CLSID_SentinelAmsi =
    {0xde3be5b6,0x4db7,0x4f8f,{0xa7,0x1c,0x05,0x76,0xcd,0xaf,0x45,0x81}};
inline constexpr ULONG kMaxContent = 1024 * 1024;

#ifdef SENTINEL_AMSI_TESTING
void SetTestBroker(const wchar_t* name, DWORD expectedPid);
#endif
