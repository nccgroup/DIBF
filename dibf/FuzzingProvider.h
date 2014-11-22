#pragma once
#include "stdafx.h"
#include "common.h"
#include "IoRequest.h"

// virtual class
class FuzzingProvider
{
public:
    // virtual BOOL init() = 0;
    virtual BOOL fuzzRequest(IoRequest*)=0;
};

class Dumbfuzzer : public FuzzingProvider
{
private:
    IoctlStorage* ioStore;
public:
    BOOL fuzzRequest(IoRequest*);
    Dumbfuzzer(IoctlStorage*);
    virtual ~Dumbfuzzer();
};