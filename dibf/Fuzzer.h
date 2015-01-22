#pragma once

#include "stdafx.h"
#include "common.h"
#include "IoRequest.h"
#include "FuzzingProvider.h"

#define STATE_FUZZING 2
#define STATE_CLEANUP 1
#define STATE_DONE 0

#define UNLFOLD_LOW_WORD(DWORD) ((DWORD<<16)|(DWORD&0xffff))

class Fuzzer
{
public:
    Fuzzer(FuzzingProvider*);
    virtual ~Fuzzer();
    static VOID Fuzzer::printDateTime(BOOL);
    // Nested class
    static  class Tracker
    {
    public:
        Tracker();
        ~Tracker();
        Fuzzer *currentFuzzer;
        HANDLE hEvent; // The event signaled by ctrl-c
        class Stats {
        public:
            VOID print();
            volatile long SentRequests;
            volatile long CompletedRequests;
            volatile long SynchronousRequests;
            volatile long ASyncRequests;
            volatile long SuccessfulRequests;
            volatile long FailedRequests;
            volatile long CanceledRequests;
            volatile long PendingRequests;
            volatile long AllocatedRequests;
        } stats;
    } tracker;
protected:
    // Vars
    HANDLE hDev;
    ULONG timeLimit;
    FuzzingProvider *fuzzingProvider;
    volatile DWORD state; // Current state
    // Functions
    BOOL InitializeFuzzersTermination();
    BOOL WaitOnTerminationEvents(ULONG);
    static BOOL __stdcall CtrlHandler(DWORD);
};