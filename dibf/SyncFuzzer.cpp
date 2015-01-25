#include "stdafx.h"
#include "SyncFuzzer.h"

SyncFuzzer::SyncFuzzer(HANDLE hDevice, ULONG timeLimit, FuzzingProvider *provider) : Fuzzer(provider)
{
    TPRINT(VERBOSITY_DEBUG, _T("AsyncFuzzer constructor\n"));
    this->hDev = hDevice;
    this->timeLimit = timeLimit;
}

SyncFuzzer::~SyncFuzzer()
{
    TPRINT(VERBOSITY_DEBUG, _T("AsyncFuzzer destructor\n"));
    return;
}

// RETURN VALUE: TRUE if success, FALSE if failure
BOOL SyncFuzzer::init()
{
    BOOL bResult=TRUE;
    return bResult;
}

DWORD SyncFuzzer::FuzzProc(PVOID param)
{
    SyncFuzzer *syncFuzzer = (SyncFuzzer*)param;
    BOOL bResult;
    ULONG nbConsecutiveFailures=0;
    IoRequest request(syncFuzzer->hDev);

    // Initialize thread's PRNG
    mt19937 prng(UNLFOLD_LOW_WORD(GetCurrentThreadId())^GetTickCount());
    while(syncFuzzer->state==STATE_FUZZING) {
        bResult = request.fuzz(syncFuzzer->fuzzingProvider, &prng);
        if(bResult) {
            bResult = request.sendSync();
            TPRINT(VERBOSITY_ALL, _T("TID[%.4u]: Sent request %#.8x (iocode %#.8x)\n"), GetCurrentThreadId(), &request, request.GetIoCode());
            InterlockedIncrement(&tracker.stats.SynchronousRequests);
            InterlockedIncrement(&tracker.stats.SentRequests);
            InterlockedIncrement(&tracker.stats.CompletedRequests);
            if(bResult) {
                InterlockedIncrement(&tracker.stats.SuccessfulRequests);
                nbConsecutiveFailures = 0;
            }
            else {
                InterlockedIncrement(&tracker.stats.FailedRequests);
                nbConsecutiveFailures++;
            }
            if(nbConsecutiveFailures==MAX_CONSECUTIVE_FAILURES) {
                TPRINT(VERBOSITY_DEFAULT, _T(" %u IOCTL failures in a row -- check config?\n"), nbConsecutiveFailures);
                nbConsecutiveFailures = 0;
            }
        }
        // No more fuzzing available from provider
        else {
            SetEvent(syncFuzzer->tracker.hEvent);
            break;
        }
    }
    return ERROR_SUCCESS;
}

BOOL SyncFuzzer::start()
{
    BOOL bResult=FALSE;
    HANDLE hThread;
    DWORD waitResult;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FuzzProc, this, 0, NULL);
    if(hThread) {
        // Wait for ctrl-c or timout
        bResult = WaitOnTerminationEvents(timeLimit);
        if(bResult) {
            state = STATE_DONE;
            waitResult = WaitForSingleObject(hThread, SYNC_CLEANUP_TIMEOUT);
            if(waitResult==WAIT_OBJECT_0) {
                TPRINT(VERBOSITY_INFO, _T("Fuzzer thread exited timely\n"));
                bResult = TRUE;
            }
            else {
                TPRINT(VERBOSITY_ERROR, _T("Fuzzer thread failed to exited timely\n"));
            }
        }
    }
    return bResult;
}
