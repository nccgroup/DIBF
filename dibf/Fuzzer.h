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
        HANDLE hEvent; // The event signaled by ctrl-c
        class Stats {
        public:
            VOID print();
            volatile unsigned long long SentRequests;
            volatile unsigned long long CompletedRequests;
            volatile unsigned long long SynchronousRequests;
            volatile unsigned long long ASyncRequests;
            volatile unsigned long long SuccessfulRequests;
            volatile unsigned long long FailedRequests;
            volatile unsigned long long CanceledRequests;
            volatile unsigned long long PendingRequests;
            volatile unsigned long long AllocatedRequests;
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
