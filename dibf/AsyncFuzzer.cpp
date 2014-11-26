#include "stdafx.h"
#include "AsyncFuzzer.h"

#define UNLFOLD_LOW_WORD(DWORD) ((DWORD<<16)|(DWORD&0xffff))

AsyncFuzzer::AsyncFuzzer(HANDLE hDevice, ULONG timeLimit, ULONG maxPending, ULONG cancelRate, FuzzingProvider *provider) : Fuzzer(provider)
{
    TPRINT(VERBOSITY_DEBUG, L"AsyncFuzzer constructor\n");
    this->hDev = hDevice;
    this->currentNbThreads = 0;
    this->startingNbThreads = 0;
    this->timeLimit = timeLimit;
    this->maxPending = maxPending;
    this->cancelRate = cancelRate;
    return;
}

AsyncFuzzer::~AsyncFuzzer()
{
    TPRINT(VERBOSITY_DEBUG, L"AsyncFuzzer destructor\n");
    // Close all handles array
    for(ULONG i=0; i<startingNbThreads&&threads[i]; i++) {
        CloseHandle(threads[i]);
    }
    // Close IO completion port
    CloseHandle(hIocp);
    // Free thread handles array
    HeapFree(GetProcessHeap(), 0, threads);
    return;
}

// RETURN VALUE: TRUE if success, FALSE if failure
BOOL AsyncFuzzer::init(ULONG nbThreads)
{
    BOOL bResult=FALSE;
    UINT nbThreadsValid=0;

    // Reset termination event
    bResult = tracker.ResetTerminationEvent();
    if(bResult) {
        // Get a valid nb of threads: MAX_THREADS if too big, twice the nb of procs if too small
        if(nbThreads>MAX_THREADS) {
            nbThreadsValid = MAX_THREADS;
            TPRINT(VERBOSITY_INFO, L"Nb of threads too big, using %d\n", MAX_THREADS);
        }
        else {
            nbThreadsValid = nbThreads ? nbThreads : GetNumberOfProcs()*2;
        }
        threads = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE)*nbThreadsValid);
        if(threads) {
            startingNbThreads = nbThreadsValid;
            if(InitializeThreadsAndCompletionPort()) {
                TPRINT(VERBOSITY_INFO, L"%u threads and IOCP created successfully\n", startingNbThreads);
                bResult = TRUE;
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Failed to create Threads and IOCP\n");
            }
        }
    }
    else {
        TPRINT(VERBOSITY_ERROR, L"Failed to reset termination event\n");
    }
    return bResult;
}

//DESCRIPTION:
// This function creates the requested number of threads, passes the config structure
// as parameter and writes the resulting handle array to the output parameter.
//
//INPUT:
// nbOfThreads - the number of threads to create
// pWorkerThreads - the ouput pointer to the thread handle array
// pAsync_config - the config struct
//
//OUTPUT:
// Returns number of threads successfully created
//
BOOL AsyncFuzzer::CreateThreads()
{
    HANDLE hThread;
    do {
        hThread = CreateThread(NULL, 0, Iocallback, this, 0, NULL);
        threads[currentNbThreads] = hThread;
        currentNbThreads++;
    }
    while(currentNbThreads<startingNbThreads && hThread);
    return (BOOL)hThread;
}

ULONG AsyncFuzzer::GetNumberOfProcs()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (UINT)(si.dwNumberOfProcessors);
}

//DESCRIPTION:
// This function creates the completion port and the requested number of threads.
// If threads creation fails, the successfully created threads' handles are closed before returning.
//
//INPUT:
// nbOfThreads - the number of threads to create
// pWorkerThreads - the ouput pointer to the thread handle array
// pAsync_config - the config struct
//
//OUTPUT:
// TRUE for success
// FALSE for error
//
BOOL AsyncFuzzer::InitializeThreadsAndCompletionPort()
{
    BOOL bResult = FALSE;

    hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0);
    if(hIocp) {
        bResult = CreateThreads();
        if(!bResult){
            TPRINT(VERBOSITY_ERROR, L"Failed to create worker threads\n", );
        }
    }
    else {
        TPRINT(VERBOSITY_ERROR, L"Failed to create I/O completion port with error %#.8x\n", GetLastError());
    }
    return bResult;
}

BOOL _inline AsyncFuzzer::AllowNewAllocation()
{
    BOOL allow=FALSE;
    ULONG looseMaxPending;

    looseMaxPending = (maxPending>startingNbThreads) ? maxPending-startingNbThreads : maxPending;
    if((ULONG)tracker.stats.PendingRequests<=looseMaxPending && tracker.stats.AllocatedRequests<=tracker.stats.PendingRequests) {
        allow=TRUE;
    }
    return allow;
}


//DESCRIPTION:
// This function is the thread proc for the async fuzzer. It dequeues requests from the io completion port,
// handles special control OVERLAPPED requests, fires IOCTLS asyncrhonously until the set maximum is reached and
// finally handles the cleanup.
//
//INPUT:
// Parameter - contains the async config structure
//
//OUTPUT:
// TRUE for success
// FALSE for error
//
//// TODO: SPLIT IN SUB FUNCTIONS
DWORD WINAPI AsyncFuzzer::Iocallback(PVOID param)
{
    INT status;
    BOOL bResult, canceled;
    DWORD nbOfBytes, error;
    ULONG_PTR specialPacket;
    LPOVERLAPPED pOvrlp;
    IoRequest *request;

    // Get asyncfuzzer
    AsyncFuzzer *asyncfuzzer = (AsyncFuzzer*)param;
    // Initialize thread's PRNG (TODO: get rid of warning)
    std::mt19937 prng = std::mt19937(UNLFOLD_LOW_WORD(GetCurrentThreadId())^GetTickCount());
    do {
        // Dequeue I/O packet
        bResult = GetQueuedCompletionStatus(asyncfuzzer->hIocp, &nbOfBytes, &specialPacket, &pOvrlp, INFINITE);
        // Handle special control overlapped types
        request = NULL;
        if(bResult) {
            if(specialPacket) {
                switch((DWORD)pOvrlp) {
                case SPECIAL_OVERLAPPED_START:
                    TPRINT(VERBOSITY_INFO, L"TID[%.4u]: Control passed to worker threads\n", GetCurrentThreadId());
                    break;
                case SPECIAL_OVERLAPPED_DONE:
                    TPRINT(VERBOSITY_INFO, L"TID[%.4u]: Received status complete notice - exiting\n", GetCurrentThreadId());
                    break;
                default:
                    TPRINT(VERBOSITY_ERROR, L"TID[%.4u]: Received unexpected special OVERLAPPED\n", GetCurrentThreadId());
                    break;
                }
            }
            else {
                if(pOvrlp){
                    // Capture the request that just completed
                    request = CONTAINING_RECORD(pOvrlp, IoRequest, overlp);
                }
            }
        }
        else {
            // This should NEVER happen
            if(!pOvrlp) {
                TPRINT(VERBOSITY_ERROR, L"TID[%.4u]: Timeout/internal error waiting for I/O completion\n", GetCurrentThreadId());
                continue; // get out
            }
            else {
                // Capture the request that just completed
                request = CONTAINING_RECORD(pOvrlp, IoRequest, overlp);
            }
        }
        // NORMAL REQUEST PROCESSING
        if(request) {
            // Accounting for completed requests
            InterlockedIncrement(&Fuzzer::tracker.stats.CompletedRequests);
            InterlockedIncrement(&Fuzzer::tracker.stats.ASyncRequests);
            if(!bResult) {
                error = GetLastError();
                if(error == ERROR_OPERATION_ABORTED) {
                    TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Async request %#.8x (iocode %#.8x) canceled successfully\n", GetCurrentThreadId(), request, request->GetIoCode());
                    InterlockedIncrement(&Fuzzer::tracker.stats.CanceledRequests);
                }
                else {
                    InterlockedIncrement(&Fuzzer::tracker.stats.FailedRequests);
                    TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Async request %#.8x (iocode %#.8x) completed with error %#.8x\n", GetCurrentThreadId(), request, request->GetIoCode(), GetLastError());
                }
            }
            else {
                InterlockedIncrement(&Fuzzer::tracker.stats.SuccessfulRequests);
                TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Async request %#.8x (iocode %#.8x) completed successfully\n", GetCurrentThreadId(), request, request->GetIoCode());
            }
            InterlockedDecrement(&Fuzzer::tracker.stats.PendingRequests);
            // All pending request are cleaned up, exit
            if(asyncfuzzer->state==STATE_CLEANUP) {
                TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Freing request %#.8x (%u currently allocated requests)\n", GetCurrentThreadId(), request, Fuzzer::tracker.stats.AllocatedRequests);
                delete request;
                InterlockedDecrement(&Fuzzer::tracker.stats.AllocatedRequests);
                if(Fuzzer::tracker.stats.AllocatedRequests==0) {
                    TPRINT(VERBOSITY_INFO, L"TID[%.4u]: Last request was processed - exiting\n", GetCurrentThreadId());
                    asyncfuzzer->state=STATE_DONE;
                    for(UINT i=0; i<asyncfuzzer->startingNbThreads-1; i++) {
                        // Unblock other threads
                        PostQueuedCompletionStatus(asyncfuzzer->hIocp, 0, SPECIAL_PACKET, SPECIAL_OVERLAPPED_DONE);
                    }
                }
            }
        }
        // Keep firing until enough requests are pending or we are finishing
        while(asyncfuzzer->state==STATE_FUZZING) {
            if(!request) {
                // Loose request allocation limit
                if(asyncfuzzer->AllowNewAllocation()) {
                    request = new IoRequest(asyncfuzzer->hDev); // Create new request
                    TPRINT(VERBOSITY_ALL, L"TID[%u]: Allocating new request in addition to the %u existing ones (%u pending)\n", GetCurrentThreadId(), Fuzzer::tracker.stats.AllocatedRequests, Fuzzer::tracker.stats.PendingRequests);
                    InterlockedIncrement(&Fuzzer::tracker.stats.AllocatedRequests);
                }
                else {
                    //TPRINT(VERBOSITY_ALL, L"TID[%u]: ENOUGH REQUESTS ALLOCATED (%d) FOR THE CURRENTLY PENDING NUMBER REQUESTS OF %d\n", GetCurrentThreadId(), Fuzzer::tracker.stats.AllocatedRequests, Fuzzer::tracker.stats.PendingRequests);
                    break;
                }
            }
            else {
                // Make sure overlapped is zeroed
                request->reset();
            }
            if(!request) {
                // TODO: WHAT THEN?
                TPRINT(VERBOSITY_ERROR, L"TID[%.4u]: Failed to allocate new request (keep going with existing %u request allocations)\n", GetCurrentThreadId(), Fuzzer::tracker.stats.AllocatedRequests);
                break;
            }
            // Craft a fuzzed request
            bResult = asyncfuzzer->fuzzingProvider->fuzzRequest(request, &prng);
            // If request fuzzed and ready for sending
            if(bResult) {
                // Fire IOCTL
                status = request->sendAsync();
                TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Sent request %#.8x (iocode %#.8x)\n", GetCurrentThreadId(), request, request->GetIoCode());
                InterlockedIncrement(&Fuzzer::tracker.stats.SentRequests);
                // Handle pending IOs
                if(status==DIBF_PENDING) {
                    // Cancel a portion of requests
                    canceled=FALSE;
                    if((ULONG)(rand()%100)<asyncfuzzer->cancelRate) {
                        canceled = CancelIoEx(asyncfuzzer->hDev, &request->overlp);
                        if(canceled) {
                            TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Sent a cancel for request %#.8x (iocode %#.8x)\n", GetCurrentThreadId(), request, request->GetIoCode());
                        }
                        else {
                            TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Failed to attempt cancelation of request %#.8x (iocode %#.8x), error %#.8x\n", GetCurrentThreadId(), request, request->GetIoCode(), GetLastError());
                        }
                    }
                    // Whether cancellation was sent or not, the request is pending
                    InterlockedIncrement(&Fuzzer::tracker.stats.PendingRequests);
                    // Will need a brand new request
                    request=NULL;
                }
                else {
                    // Displaying synchronous completion result
                    InterlockedIncrement(&Fuzzer::tracker.stats.CompletedRequests);
                    InterlockedIncrement(&Fuzzer::tracker.stats.SynchronousRequests);
                    if(status==DIBF_SUCCESS){
                        InterlockedIncrement(&Fuzzer::tracker.stats.SuccessfulRequests);
                        TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Request %#.8x (iocode %#.8x) synchronously completed successfully\n", GetCurrentThreadId(), request, request->GetIoCode());
                    }
                    else {
                        InterlockedIncrement(&Fuzzer::tracker.stats.FailedRequests);
                        TPRINT(VERBOSITY_ALL, L"TID[%.4u]: Request %#.8x (iocode %#.8x) synchronously completed with error %#.8x\n", GetCurrentThreadId(), request, request->GetIoCode(), GetLastError());
                    }
                }
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"TID[%.4u]: Failed to craft fuzzed request\n");
            }
        } // while firing ioctl
    } while(asyncfuzzer->state!=STATE_DONE);
    return 0;
}

//DESCRIPTION:
// This function is the entry point for the async fuzzer. It packs all params in the config structure
// and passes it to its initialization function. It then associates the device passed as parameter to
// the completion port and passes control to the worker threads by posting an empty completion status.
//
//INPUT:
// hDev - device to fuzz
// pIoctlstorage - the list of ioctls
// dwIOCTLCount - the count of ioctls in pIoctlstorage
// nbOfThreadsRequested - the requested number of threads
// timeLimit - an array containing the 3 timouts (for each fuzzer)
// maxPending - the max number of pending requests for the async fuzzer
// cancelRate - percentage of pending requests to attempt to cancel for the async fuzzer
// pStats - the statistics stats pointer
//OUTPUT:
// TRUE for success
// FALSE for error
//
BOOL AsyncFuzzer::start()
{
    BOOL bResult = FALSE;
    DWORD waitResult;

    bResult = SetFileCompletionNotificationModes(hDev, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
    if(!bResult) {
        TPRINT(VERBOSITY_ERROR, L"Failed to configure iocompletion port with error %#.8x\n", GetLastError());
    }
    // Associate this dev handle to iocp
    CreateIoCompletionPort(hDev, hIocp, 0, 0);
    // Pass control to the iocp handler
    if(!PostQueuedCompletionStatus(hIocp, 0, SPECIAL_PACKET, SPECIAL_OVERLAPPED_START)) {
        TPRINT(VERBOSITY_ERROR, L"Failed to post completion status to completion port\n");
    }
    // Wait for ctrl-c or timout
    bResult = tracker.WaitOnTerminationEvent(timeLimit);
    if(bResult) {
        state=STATE_CLEANUP;
            waitResult = WaitForMultipleObjects(startingNbThreads, threads, TRUE, INFINITE);
            if(waitResult==WAIT_OBJECT_0) {
                TPRINT(VERBOSITY_INFO, L"All fuzzer threads exited timely\n");
                bResult = TRUE;
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Not all worker threads exited timely\n");
            }
        }
    else {
        TPRINT(VERBOSITY_ERROR, L"Failed wait on termination event\n");
    }
    return bResult;
}
