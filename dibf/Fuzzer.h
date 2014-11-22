#pragma once

#include "stdafx.h"
#include "common.h"
#include "IoRequest.h"

#define STATE_FUZZING 2
#define STATE_CLEANUP 1
#define STATE_DONE 0

class Fuzzer
{
public:
    Fuzzer(IoctlStorage*);
    virtual ~Fuzzer();
    // Nested class
    static  class StaticFuzzerInitializer
    {
    public:
        StaticFuzzerInitializer();
        virtual ~StaticFuzzerInitializer();
        HANDLE hEvent;
        class Tracker {
        // TODO: MAKE MEMBERS PRIVATE AND IMPLEMENT PUBLIC ACCESSORS
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
        } tracker;
    } s_init; // The event signaled by ctrl-c
protected:
    // Members
    HANDLE hDev;
    IoctlStorage *ioctls;
    ULONG timeLimit;
    // Functions
    BOOL InitializeFuzzersTermination();
    volatile DWORD state;
    static BOOL __stdcall CtrlHandler(DWORD);
};