#pragma once

#include "stdafx.h"
#include "common.h"
#include "IoRequest.h"
#include "FuzzingProvider.h"

#define STATE_FUZZING 2
#define STATE_CLEANUP 1
#define STATE_DONE 0

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
        virtual ~Tracker();
        BOOL SetTerminationEvent();
        BOOL ResetTerminationEvent();
        BOOL WaitOnTerminationEvent(ULONG);
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
    private:
        HANDLE hEvent; // The event signaled by ctrl-c
    } tracker;
protected:
    // Vars
    HANDLE hDev;
    IoctlStorage *ioctls;
    ULONG timeLimit;
    FuzzingProvider *fuzzingProvider;
    // Functions
    BOOL InitializeFuzzersTermination();
    volatile DWORD state;
    static BOOL __stdcall CtrlHandler(DWORD);
};