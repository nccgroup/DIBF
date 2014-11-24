#pragma once
#include "stdafx.h"
#include "common.h"
#include "IoRequest.h"

// Pure virtual class
class FuzzingProvider
{
public:
    FuzzingProvider();
    virtual ~FuzzingProvider() = 0;
    virtual BOOL fuzzRequest(IoRequest*, std::mt19937*) = 0;
};

class Dumbfuzzer : public FuzzingProvider
{
private:
    IoctlStorage* ioStore;
public:
    BOOL fuzzRequest(IoRequest*, std::mt19937*);
    Dumbfuzzer(IoctlStorage*);
    virtual ~Dumbfuzzer();
};