#include "stdafx.h"
#include "AsyncFuzzer.h"

Fuzzer::StaticFuzzerInitializer Fuzzer::s_init;

// Trivial constructor
Fuzzer::Fuzzer(IoctlStorage *iost) : ioctls(iost)
{
    state=STATE_FUZZING;
}

// Simple destructor
Fuzzer::~Fuzzer() {
    HeapFree(GetProcessHeap(), 0, ioctls);
}

//DESCRIPTION:
// Control handler for CTRL-C handling.
//
//INPUT:
// fdwCtrlType - Received code.
//
//
//OUTPUT:
// TRUE - Handled
// FALSE - Forward to next registered handler
//
BOOL __stdcall Fuzzer::CtrlHandler(DWORD fdwCtrlType)
{
    if(fdwCtrlType==CTRL_C_EVENT || fdwCtrlType==CTRL_BREAK_EVENT)
    {
        // This triggers the end of fuzzing stage
        SetEvent(s_init.hEvent);
        return TRUE;
    }
    return FALSE;
}

//DESCRIPTION:
// Creates the all-fuzzers-wide bail event and registers CTRL-C handler
//
//INPUT:
// None
//
//OUTPUT:
// BOOL SUCCESS/FAILURE
//
Fuzzer::StaticFuzzerInitializer::StaticFuzzerInitializer()
{
    // Create the MANUAL-RESET bail event
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(hEvent) {
        // Register ctrl-c handler
        if(SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
            // TODO: CHANGE THIS TO PRINT ONLY INFO_ALL
            TPRINT(LEVEL_ALWAYS_PRINT, L"SUCCESSFULLY INITIALIZED AND REGISTERED TERMINATION EVENT HANDLER\n");
        }
        else {
            TPRINT(LEVEL_WARNING, L"WARNING: FAILED TO REGISTER CONTROL HANDLER - CTRL-C will not work as expected\n");
        }
    }
    else {
        TPRINT(LEVEL_ERROR, L"Failed to create event, error %x\n", GetLastError());
    }
    return;
}

Fuzzer::StaticFuzzerInitializer::~StaticFuzzerInitializer()
{
    if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, FALSE)) {
        TPRINT(LEVEL_WARNING, L"\n WARNING: FAILED TO UNREGISTER CONTROL HANDLER\n");
    }
}

//DESCRIPTION:
// This function prints the RUN STARTED/RUN ENDED date & time string
//
//INPUT:
// ended - boolean controlling whether to print "RUN ENDED" OR "RUN STARTED"
//
//OUTPUT:
// None
//
// TODO: PUT THIS IN COMMON CLASS
VOID printDateTime(BOOL ended)
{
    TCHAR timestr[64];
    TCHAR datestr[64];
    LPTSTR fmt = ended ? L"RUN ENDED: %s %s\n" : L"RUN STARTED: %s %s\n";

    // Print date & time
    if(GetDateFormat(LOCALE_USER_DEFAULT, 0, NULL, NULL, datestr, 32) && GetTimeFormat(LOCALE_USER_DEFAULT, TIME_NOSECONDS, NULL, NULL, timestr, 32)) {
        TPRINT(LEVEL_ALWAYS_PRINT, fmt, datestr, timestr);
    }
    else {
        TPRINT(LEVEL_ALWAYS_PRINT, L"TIME NOT AVAILABLE\n");
    }
    return;
}

//DESCRIPTION:
// This function prints the cummulative tracked statitists
//
//INPUT:
// pTracker - Pointer to the tracker struct
//
//OUTPUT:
// None
VOID Fuzzer::StaticFuzzerInitializer::Tracker::print()
{
    // Wait for all the volatile writes to go through
    MemoryBarrier();
    // clean print
    fflush(stdout);
    // Print summary
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Sent Requests : %d\n", SentRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"Completed Requests : %d (%d sync, %d async)\n", CompletedRequests, SynchronousRequests, ASyncRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"SuccessfulRequests : %d\n", SuccessfulRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"FailedRequests : %d\n", FailedRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"CanceledRequests : %d\n", CanceledRequests);
    TPRINT(LEVEL_INFO_ALL, L"----\n");
    TPRINT(LEVEL_INFO_ALL, L"Consistent Results: %s\n", SuccessfulRequests
        +FailedRequests
        +CanceledRequests
        == CompletedRequests ? L"YES" : L"NO (it's ok)");
    TPRINT(LEVEL_INFO_ALL, L"Cleanup completed: %s (%u request%s still allocated)\n", !AllocatedRequests ? L"YES" : L"NO", AllocatedRequests, AllocatedRequests>1?L"s":L"");
    TPRINT(LEVEL_INFO_ALL, L"----\n");
    printDateTime(TRUE);
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n\n");
    return;
}