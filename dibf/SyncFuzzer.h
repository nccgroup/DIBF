#pragma once
#include "stdafx.h"
#include "common.h"
#include "Fuzzer.h"
#include "FuzzingProvider.h"

#define MAX_CONSECUTIVE_FAILURES 4096
#define SYNC_CLEANUP_TIMEOUT 1000 // 1s for threads to do cleanup

class SyncFuzzer : public Fuzzer
{
public:
    SyncFuzzer(HANDLE, ULONG, FuzzingProvider*);
    ~SyncFuzzer();
    BOOL init();
    BOOL start();
private:
    static DWORD WINAPI FuzzProc(PVOID);
};
