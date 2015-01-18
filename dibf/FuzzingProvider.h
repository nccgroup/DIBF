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
