#pragma once
#include "stdafx.h"
#include "common.h"

// Pure virtual class
class FuzzingProvider
{
public:
    FuzzingProvider();
    virtual ~FuzzingProvider() = 0;
    virtual BOOL GetRandomIoctlAndBuffer(PDWORD, vector<UCHAR>**, mt19937*)=0;
    HANDLE hEvent;
    BOOL canGoCold;
};

class Dumbfuzzer : public FuzzingProvider
{
public:
    Dumbfuzzer(IoctlStorage*);
    ~Dumbfuzzer();
    BOOL GetRandomIoctlAndBuffer(PDWORD, vector<UCHAR>**, mt19937*);
private:
    IoctlStorage* ioStore;
};

class SlidingDwordFuzzer : public FuzzingProvider
{
public:
    SlidingDwordFuzzer(IoctlStorage*);
    ~SlidingDwordFuzzer();
    BOOL GetRandomIoctlAndBuffer(PDWORD, vector<UCHAR>**, mt19937*);
private:
    IoctlStorage* ioStore;
    static CONST DWORD DWORDArray[];
    volatile UINT ioctlIndex, iteration, position;
};

class NamedPipeInputFuzzer : public FuzzingProvider
{
public:
    NamedPipeInputFuzzer();
    ~NamedPipeInputFuzzer();
    BOOL Init();
    BOOL GetRandomIoctlAndBuffer(PDWORD, vector<UCHAR>**, mt19937*);
private:
    HANDLE dibf_pipe;
    HANDLE inputThread;
    CRITICAL_SECTION lock;
    static DWORD WINAPI FuzzInputProc(PVOID);
    queue<vector<UCHAR>*> iopackets; // TODO: swap this for a lockless ringbuffer
};
