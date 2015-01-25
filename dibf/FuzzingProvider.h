#pragma once
#include "stdafx.h"
#include "common.h"

// Pure virtual class
class FuzzingProvider
{
public:
    FuzzingProvider();
    virtual ~FuzzingProvider() = 0;
    virtual BOOL GetRandomIoctlAndBuffer(DWORD&, vector<UCHAR>&, mt19937*)=0;
    HANDLE hEvent;
    BOOL canGoCold;
};

class Dumbfuzzer : public FuzzingProvider
{
public:
    Dumbfuzzer(const vector<IoctlDef>&);
    ~Dumbfuzzer();
    BOOL GetRandomIoctlAndBuffer(DWORD&, vector<UCHAR>&, mt19937*);
    Dumbfuzzer & operator=( const Dumbfuzzer & ) { return *this; }
private:
    const vector<IoctlDef> ioStore;
};

class SlidingDwordFuzzer : public FuzzingProvider
{
public:
    SlidingDwordFuzzer(const vector<IoctlDef>&);
    ~SlidingDwordFuzzer();
    BOOL GetRandomIoctlAndBuffer(DWORD&, vector<UCHAR>&, mt19937*);
    SlidingDwordFuzzer & operator=( const SlidingDwordFuzzer & ) { return *this; }
private:
    const vector<IoctlDef> ioStore;
    static CONST DWORD DWORDArray[];
    volatile UINT ioctlIndex, iteration, position;
};

class NamedPipeInputFuzzer : public FuzzingProvider
{
public:
    NamedPipeInputFuzzer();
    ~NamedPipeInputFuzzer();
    BOOL Init();
    BOOL GetRandomIoctlAndBuffer(DWORD&, vector<UCHAR>&, mt19937*);
private:
    HANDLE dibf_pipe;
    HANDLE inputThread;
    CRITICAL_SECTION lock;
    BOOL bExit;
    static DWORD WINAPI FuzzInputProc(PVOID);
    queue<vector<UCHAR>*> iopackets; // TODO: swap this for a lockless ringbuffer
};
