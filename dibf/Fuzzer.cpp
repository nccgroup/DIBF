#include "stdafx.h"
#include "AsyncFuzzer.h"

Fuzzer::StaticFuzzerInitializer Fuzzer::s_init;

// Trivial constructor
Fuzzer::Fuzzer(FuzzingProvider *p) : fuzzingProvider(p)
{
    state=STATE_FUZZING;
}

// Simple destructor
Fuzzer::~Fuzzer() {
    delete fuzzingProvider;
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
        if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
            TPRINT(VERBOSITY_INFO, L"Failed to register control handler, ctrl-c will not work as expected\n");
        }
    }
    else {
        TPRINT(VERBOSITY_ERROR, L"Failed to create event, error %x\n", GetLastError());
    }
    return;
}

Fuzzer::StaticFuzzerInitializer::~StaticFuzzerInitializer()
{
    if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, FALSE)) {
        TPRINT(VERBOSITY_INFO, L"Failed to unregister control handler\n");
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
VOID Fuzzer::printDateTime(BOOL ended)
{
    TCHAR timestr[64];
    TCHAR datestr[64];
    LPTSTR fmt = ended ? L"Run ended: %s %s\n" : L"Run started: %s %s\n";

    // Print date & time
    if(GetDateFormat(LOCALE_USER_DEFAULT, 0, NULL, NULL, datestr, 32) && GetTimeFormat(LOCALE_USER_DEFAULT, TIME_NOSECONDS, NULL, NULL, timestr, 32)) {
        TPRINT(VERBOSITY_DEFAULT, fmt, datestr, timestr);
    }
    else {
        TPRINT(VERBOSITY_DEFAULT, L"Time unavailable\n");
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
    TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------\n");
    TPRINT(VERBOSITY_DEFAULT, L"Sent Requests : %d\n", SentRequests);
    TPRINT(VERBOSITY_DEFAULT, L"Completed Requests : %d (%d sync, %d async)\n", CompletedRequests, SynchronousRequests, ASyncRequests);
    TPRINT(VERBOSITY_DEFAULT, L"SuccessfulRequests : %d\n", SuccessfulRequests);
    TPRINT(VERBOSITY_DEFAULT, L"FailedRequests : %d\n", FailedRequests);
    TPRINT(VERBOSITY_DEFAULT, L"CanceledRequests : %d\n", CanceledRequests);
    TPRINT(VERBOSITY_INFO, L"----\n");
    TPRINT(VERBOSITY_INFO, L"Consistent Results: %s\n", SuccessfulRequests
        +FailedRequests
        +CanceledRequests
        == CompletedRequests ? L"Yes" : L"No (it's ok)");
    // Cleanup completed
    if(!AllocatedRequests && !PendingRequests) {
        TPRINT(VERBOSITY_INFO, L"Cleanup completed, no request still allocated or pending\n");
    }
    else {
        TPRINT(VERBOSITY_INFO, L"Cleanup incomplete, %u request%s still allocated, %u pending\n", AllocatedRequests, AllocatedRequests>1?L"s":L"", PendingRequests);
    }
    TPRINT(VERBOSITY_ALL, L"----\n");
    printDateTime(TRUE);
    TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------\n\n");
    return;
}