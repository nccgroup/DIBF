// FastFuzzer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Fuzzers.h"

// Static variables for fuzzers
static HANDLE s_bailEvent; // The event signaled by ctrl-c

//DESCRIPTION:
// Creates the all-fuzzers-wide bail event and registers CTRL-C handler
//
//INPUT:
// None
//
//OUTPUT:
// BOOL SUCCESS/FAILURE
//
BOOL InitializeFuzzersTermination()
{
    BOOL bResult=FALSE;

    // Create the MANUAL-RESET bail event
    s_bailEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(s_bailEvent) {
        bResult=TRUE;
        // Register ctrl-c handler
        if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
            TPRINT(LEVEL_WARNING, L"\n WARNING: FAILED TO REGISTER CONTROL HANDLER\n");
        }
    }
    else {
        TPRINT(LEVEL_ERROR, L"Failed to create event, error %x\n", GetLastError());
    }
    return bResult;
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
BOOL __stdcall CtrlHandler(DWORD fdwCtrlType)
{
    if(fdwCtrlType==CTRL_C_EVENT || fdwCtrlType==CTRL_BREAK_EVENT)
    {
        // This triggers the end of fuzzing stage
        SetEvent(s_bailEvent);
        return TRUE;
    }

    return FALSE;
}

//DESCRIPTION:
// Fuzzes the device by sending randomized input.
//
//INPUT:
// hDevice - Handle to device object.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
//
//OUTPUT:
// None.
//
DWORD WINAPI RandomFuzzer(PVOID param)
{
    BOOL bResult;
    volatile DWORD *terminate;
    HANDLE hDevice;
    PTRACKER pTracker;
    PSYNC_CONFIG pConfig;
    PIOCTL_STORAGE pIOCTLStorage;
    CHAR *pDummyBuffer=NULL, cOutputBuffer[DUMMY_SIZE];
    DWORD dwCurrentIOCTLIndex, i, dwBytesReturned, dwSize, dwIOCTLCount;
    ULONG nbConsecutiveFailures = 0; // nb of failures in a row

    // Capture params
    pConfig = (PSYNC_CONFIG)param;
    hDevice = pConfig->hDev;
    pIOCTLStorage = pConfig->ioctls;
    dwIOCTLCount = pConfig->count;
    terminate = pConfig->terminate;
    pTracker = pConfig->pTracker;
    // PRNG root
    srand((UINT)time(NULL));
    // Allocate fuzz buffer
    pDummyBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), 0, MAX_BF_BUFFER_SIZE);
    if(pDummyBuffer) {
        while(!(*terminate)) {
            if(nbConsecutiveFailures<CONSECUTIVE_FAILURES) {
                dwCurrentIOCTLIndex = (dwIOCTLCount>1) ? rand()%dwIOCTLCount : 0;
                if(pIOCTLStorage[dwCurrentIOCTLIndex].dwLowerSize>MAX_BF_BUFFER_SIZE || pIOCTLStorage[dwCurrentIOCTLIndex].dwLowerSize==INVALID_BUFFER_SIZE) {
                    TPRINT(LEVEL_INFO_ALL, L" SKIPPING IOCTL REQUIRING INPUT BUFFER %d BYTES\n", pIOCTLStorage[dwCurrentIOCTLIndex].dwLowerSize);
                    continue;
                }
                dwSize = pIOCTLStorage[dwCurrentIOCTLIndex].dwUpperSize ? rand()%pIOCTLStorage[dwCurrentIOCTLIndex].dwUpperSize : pIOCTLStorage[dwCurrentIOCTLIndex].dwLowerSize;
                for(i=0; i<dwSize; i++) {
                    pDummyBuffer[i] = rand()&0xff;
                }
                if(!(pTracker->CompletedRequests%1024)) {
                    TPRINT(LEVEL_INFO, L"%d IOCTL completed\n", pTracker->CompletedRequests);
                }
                bResult = DeviceIoControl(hDevice, pIOCTLStorage[dwCurrentIOCTLIndex].dwIOCTL, pDummyBuffer, dwSize,cOutputBuffer, DUMMY_SIZE, &dwBytesReturned, NULL);
                InterlockedIncrement(&pTracker->SynchronousRequests);
                InterlockedIncrement(&pTracker->SentRequests);
                InterlockedIncrement(&pTracker->CompletedRequests);
                if(bResult) {
                    TPRINT(LEVEL_INFO_ALL, L"IOCTL: %#.8x Size: %d completed successfully\n", pIOCTLStorage[dwCurrentIOCTLIndex].dwIOCTL, dwSize);
                    InterlockedIncrement(&pTracker->SuccessfulRequests);
                    nbConsecutiveFailures = 0; // reset
                }
                else {
                    TPRINT(LEVEL_INFO_ALL, L"IOCTL: %#.8x Size: %d failed with error %#.8x\n", pIOCTLStorage[dwCurrentIOCTLIndex].dwIOCTL, dwSize, GetLastError());
                    InterlockedIncrement(&pTracker->FailedRequests);
                    nbConsecutiveFailures++;
                }
            }
            else {
                TPRINT(LEVEL_ALWAYS_PRINT, L" !!!! %d IOCTL failures in a row -- trying again in 10 seconds (press CTRL-C to finish run) !!!!\n", nbConsecutiveFailures);
                Sleep(10000);
                nbConsecutiveFailures = 0;
            }
        }
        HeapFree(GetProcessHeap(), 0, pDummyBuffer);
    } // if pDummyBuffer
    else {
        TPRINT(LEVEL_ERROR, L"Failed to allocate dummy buffer\n");
    }
    return 0;
}

//DESCRIPTION:
// Fuzzes the device by sliding various problematic DWORDs through the buffer.
//
//INPUT:
// hDevice - Handle to device object.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
//
//OUTPUT:
// None.
//
DWORD WINAPI SlidingDWORDFuzzer(PVOID param)
{
    BOOL bResult;
    volatile DWORD *terminate;
    HANDLE hDevice;
    PTRACKER pTracker;
    PSYNC_CONFIG pConfig;
    PIOCTL_STORAGE pIOCTLStorage;
    DWORD dwIOCTLCount, dwIOCTLIndex=0, dwSlideIterations, i, j, dwBytesReturned;
    PBYTE pDummyBuffer = NULL,pCurrentPosition = NULL;
    CONST DWORD DWORDArray[] = {0x0fffffff, 0x10000000, 0x1fffffff, 0x20000000, 0x3fffffff, 0x40000000, 0x7fffffff, 0x80000000, 0xffffffff};
    ULONG nbConsecutiveFailures = 0; // nb of failures in a row

    // Capture params
    pConfig = (PSYNC_CONFIG)param;
    hDevice=pConfig->hDev;
    pIOCTLStorage=pConfig->ioctls;
    dwIOCTLCount=pConfig->count;
    terminate = pConfig->terminate;
    pTracker=pConfig->pTracker;

    pDummyBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BF_BUFFER_SIZE);
    if(pDummyBuffer) {
        while(!(*terminate) && (dwIOCTLIndex < dwIOCTLCount) && (pIOCTLStorage[dwIOCTLIndex].dwIOCTL != 0)) {
            if(pIOCTLStorage[dwIOCTLIndex].dwLowerSize!=INVALID_BUFFER_SIZE) {
                TPRINT(LEVEL_INFO, L" Working on IOCTL %#.8x\n", pIOCTLStorage[dwIOCTLIndex].dwIOCTL);
                dwSlideIterations = pIOCTLStorage[dwIOCTLIndex].dwUpperSize-4+1;
                pCurrentPosition = pDummyBuffer;
                for(i=1; !(*terminate) && i<dwSlideIterations; i++) {
                    for(j=0; j<sizeof(DWORDArray)/sizeof(DWORD); j++) {
                        if(nbConsecutiveFailures<CONSECUTIVE_FAILURES) {
                            *((DWORD*)pCurrentPosition) = DWORDArray[j];
                            TPRINT(LEVEL_INFO_ALL, L"IOCTL: %#.8x | position %d | DWORD: %#.8x\n", pIOCTLStorage[dwIOCTLIndex].dwIOCTL, i, DWORDArray[j]);
                            bResult = DeviceIoControl(hDevice, pIOCTLStorage[dwIOCTLIndex].dwIOCTL, pDummyBuffer, pIOCTLStorage[dwIOCTLIndex].dwUpperSize, pDummyBuffer, MAX_BF_BUFFER_SIZE, &dwBytesReturned, NULL);
                            InterlockedIncrement(&pTracker->SynchronousRequests);
                            InterlockedIncrement(&pTracker->SentRequests);
                            InterlockedIncrement(&pTracker->CompletedRequests);
                            if(bResult) {
                                InterlockedIncrement(&pTracker->SuccessfulRequests);
                                nbConsecutiveFailures = 0;
                            }
                            else {
                                InterlockedIncrement(&pTracker->FailedRequests);
                                nbConsecutiveFailures++;
                            }
                        }
                        else {
                            TPRINT(LEVEL_ALWAYS_PRINT, L" !!!! %d IOCTL failures in a row -- skipping IOCTL %#.8x !!!!\n", nbConsecutiveFailures, pIOCTLStorage[dwIOCTLIndex].dwIOCTL);
                            nbConsecutiveFailures = 0;
                            break;
                        }
                    }
                    *((DWORD*)pCurrentPosition) = 0;
                    pCurrentPosition++;
                }
            }
            dwIOCTLIndex++;
        }
    HeapFree(GetProcessHeap(), 0, pDummyBuffer);
} // if pDummyBuffer
    return 0;
}

VOID StartSyncFuzzer(LPTHREAD_START_ROUTINE fuzzRoutine, HANDLE hDevice, PIOCTL_STORAGE pIOCTLStorage, DWORD dwIOCTLCount, ULONG timeLimit, PTRACKER pTracker)
{
    HANDLE hThread;
    DWORD waitResult;
    volatile DWORD terminate;
    SYNC_CONFIG config = {hDevice, dwIOCTLCount, pIOCTLStorage, &terminate, pTracker};

    terminate = FALSE;
    ResetEvent(s_bailEvent);
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fuzzRoutine, &config, 0, NULL);
    if(hThread) {
        waitResult = WaitForSingleObject(s_bailEvent, timeLimit*1000);
        if(waitResult==WAIT_FAILED) {
            TPRINT(LEVEL_ERROR, L"Failed wait on termination event.\n");
        }
        // Signal termination
        terminate = TRUE;
        // Wait for thread to be done
        waitResult = WaitForSingleObject(hThread, CLEANUP_TIMEOUT);
        if(waitResult==WAIT_FAILED) {
            TPRINT(LEVEL_ERROR, L"Failed wait on thread termination.\n");
        }
        CloseHandle(hThread);
    }
    else {
        TPRINT(LEVEL_ERROR, L"Failed to start synchronous fuzzer thread, error %x\n", GetLastError());
    }
    return;
}

// NOT CHECKING HEAPFREE() for error. If that happens, we're in the bad anyway and it's too late
BOOL CleanupRequest(PIOCTL_REQUEST pRequest)
{
    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: FREEING REQUEST %x\n", GetCurrentThreadId(), pRequest);
    HeapFree(GetProcessHeap(), 0x0, pRequest->FuzzBuf);
    HeapFree(GetProcessHeap(), 0x0, pRequest->OutBuf);
    HeapFree(GetProcessHeap(), 0x0, pRequest);
    pRequest = NULL;
    return TRUE;
}

PIOCTL_REQUEST createRequest(DWORD code, DWORD inSize, DWORD outSize)
{
    PIOCTL_REQUEST request;

    request = (PIOCTL_REQUEST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IOCTL_REQUEST));
    if(request) {
        request->iocode = code;
        request->FuzzBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, inSize);
        if(!request->FuzzBuf) {
            TPRINT(LEVEL_ERROR, L"ALLOC FAILED, FREEING 1 BUFFER AND EXITING\n");
            HeapFree(GetProcessHeap(), 0x0, request);
            request = NULL;
        }
        else {
            request->OutBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSize);
            if(!request->OutBuf) {
                TPRINT(LEVEL_INFO, L"ALLOC FAILED, FREEING 2 BUFFERS AND EXITING\n");
                HeapFree(GetProcessHeap(), 0x0, request->FuzzBuf);
                HeapFree(GetProcessHeap(), 0x0, request);
                request = NULL;
            } else {
                // ALlocations succeeded
                request->inSize = inSize;
                request->outSize = outSize;
                TPRINT(LEVEL_INFO_ALL, L"TID[%x]: NEW REQUEST %#.8x ALLOCATED\n", GetCurrentThreadId(), request);
            }
        }
    }
    else {
        TPRINT(LEVEL_ERROR, L"REQUEST ALLOCATION FAILED.\n");
    }
    return request;
}

//DESCRIPTION:
// Determine the number of cores (hyper-threaded virtual cores) on the system
//
//INPUT:
// None.
//
//OUTPUT:
// the number of cores on the system
//
UINT GetNumberOfProcs()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (UINT)(si.dwNumberOfProcessors);
}

//DESCRIPTION:
// Reassign a request with a new io code and reallocs the input buffer if necessary.
//
//INPUT:
// request - the request to reassign
// iocode - the new iocode
// size - the new size for input buffer
//OUTPUT:
// TRUE for success
// FALSE for error
//
BOOL FixRequest(PIOCTL_REQUEST request, DWORD iocode, DWORD size)
{
    PUCHAR newBuf;

    request->iocode = iocode;
    // Only realloc if current size is different
    if(request->inSize != size) {
        newBuf = (UCHAR*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, request->FuzzBuf, size);
        if(newBuf) {
            request->FuzzBuf = newBuf;
            request->inSize = size;
        }
        else {
            TPRINT(LEVEL_WARNING, L"Reallocation for request failed\n");
            CleanupRequest(request);
        }
    }
    return (request&&request->FuzzBuf) ? TRUE : FALSE;
}

//DESCRIPTION:
// This function eventually recycles a given request, and sends a random io request
// picked from the ioctl storage to the given device.
//
//INPUT:
// hDev - device to send ioctl to
// ReusableRequest - pointer to a request to reuse or allocate - this is also the function's success/failure indicator
// pIoctlstorage - the list of ioctls
// ioctlcount - the count of ioctls in pIoctlstorage
// pTracker - the statistics tracker pointer
//
//OUTPUT:
// Return value:
//      SUCCESS - the request successfully completey synchronously
//      N_ERROR - the request failed synchronously
//      PENDING - the reqest is pending
// *ReusableRequest
//      NULL - function failed to get a request
//      NON_NULL- successfully got a request to send
//
INT SendIoctl(HANDLE hDev, PIOCTL_REQUEST *ReusableRequest, PIOCTL_STORAGE pIoctlstorage, DWORD ioctlcount, PTRACKER pTracker)
{
    INT status=SUCCESS;
    BOOL bResult;
    DWORD FuzzBufSize,OutBufSize=1024, dwIOCTL, i, dwIndex=0, maxlen;
    PIOCTL_REQUEST request = NULL;

    dwIndex = rand()%ioctlcount;
    dwIOCTL = pIoctlstorage[dwIndex].dwIOCTL;
    maxlen = pIoctlstorage[dwIndex].dwUpperSize-pIoctlstorage[dwIndex].dwLowerSize;
    FuzzBufSize = maxlen ? pIoctlstorage[dwIndex].dwLowerSize + (rand()%maxlen) : pIoctlstorage[dwIndex].dwLowerSize;
    // If we have a reusable request
    if(*ReusableRequest) {
        request = *ReusableRequest;
        FixRequest(request, dwIOCTL, FuzzBufSize);
    }
    // Otherwise allocate a new one
    else {
        request = createRequest(dwIOCTL, FuzzBufSize, OutBufSize);
        if(request) {
            InterlockedIncrement(&pTracker->AllocatedRequests);
        }
        *ReusableRequest = request;
    }
    // At this point we must have a request - freshly allocated or reused
    if(request){
        // Either way, use new overlapped
        ZeroMemory(&request->overlp, sizeof(OVERLAPPED));
        // Fill the buffer with random bytes
        for(i = 0; i < request->inSize; i++) {
            request->FuzzBuf[i] = (UCHAR)(rand()&0xff);
        }

        TPRINT(LEVEL_INFO_ALL, L"TID[%x]: SENDING REQUEST %#.8x (IOCODE %#.8x)\n", GetCurrentThreadId(), request, request->iocode);
        bResult = DeviceIoControl(hDev, request->iocode, request->FuzzBuf, request->inSize, request->OutBuf, request->outSize, NULL, &request->overlp);
        // Pending or Failed
        if(!bResult) {
            // Return pending
            if(GetLastError() == ERROR_IO_PENDING) {
                status = PENDING;
            }
            else {
                status = N_ERROR;
            }
        }
    }
    else {
        TPRINT(LEVEL_ERROR, L"TID[%x]: Request management failure\n", GetCurrentThreadId());
        status = N_ERROR;
    }
    return status;
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
DWORD WINAPI Iocallback(PVOID Parameter)
{
    INT status;
    HANDLE hDev, hIocp;
    ULONG maxPending, cancelRate;
    UINT startingNbThreads;
    BOOL bResult, canceled, tbail=FALSE, cleanup=FALSE, gotRequest=TRUE;
    DWORD nbOfBytes, error;
    ULONG_PTR completionKey;
    LPOVERLAPPED pOvrlp;
    PIOCTL_REQUEST request=NULL;
    PTRACKER pTracker;
    PASYNC_CONFIG pAsync_config = PASYNC_CONFIG(Parameter);

    // Init from config struct
    hDev = pAsync_config->hDev;
    hIocp = pAsync_config->hIocp;
    maxPending = pAsync_config->maxPending;
    cancelRate = pAsync_config->cancelRate;
    startingNbThreads = pAsync_config->startingNbThreads;
    pTracker = pAsync_config->pTracker;
    // TODO: merge 'bail' and 'cleanup' into state
    do {
        // Dequeue I/O packet
        bResult = GetQueuedCompletionStatus(hIocp, &nbOfBytes, &completionKey, &pOvrlp, INFINITE);

        // TIME OUT HANDLING
        if(!bResult && !pOvrlp) {
            TPRINT(LEVEL_ERROR, L"TID[%x]: TIMEOUT/INTERNAL ERROR WAITING FOR I/O COMPLETION\n", GetCurrentThreadId());
            continue; // get out
        }
        gotRequest=TRUE; // Default case is a regular request completing
        // Handle special control overlapped types
        if(bResult) {
            if(!pOvrlp) {
                request = NULL;
                TPRINT(LEVEL_INFO, L"TID[%x]: CONTROL PASSED TO WORKER THREADS\n", GetCurrentThreadId());
                gotRequest = FALSE;
            }
            else {
                // This thread will send signals to all others
                if(pOvrlp==SPECIAL_OVERLAPPED_BAIL_ALL) {
                    tbail = TRUE;
                    TPRINT(LEVEL_INFO, L"TID[%x]: RECEIVED TERMINATION SIGNAL\n", GetCurrentThreadId());
                    for(UINT i=0; i<startingNbThreads-1; i++) {
                        // Since this thread will never dequeue again, it will never receive both SPECIAL_OVELRAPPEDS
                        // ... unless all other threads exited already meaning all SPECIAL_OVERLAPPED_BAIL have been dequeued already :)
                        PostQueuedCompletionStatus(hIocp, 0, 0, SPECIAL_OVERLAPPED_BAIL);
                        gotRequest = FALSE;
                    }
                }
                else {
                    if(pOvrlp==SPECIAL_OVERLAPPED_BAIL) {
                        TPRINT(LEVEL_INFO_ALL, L"TID[%x]: RECEIVED TERMINATIONL SIGNAL\n", GetCurrentThreadId());
                        tbail = TRUE;
                        gotRequest = FALSE;
                    }
                }
            }
        }

        // NORMAL REQUEST PROCESSING
        if(gotRequest) {
            // Capture the request that just completed
            request = CONTAINING_RECORD(pOvrlp, IOCTL_REQUEST, overlp);
            // Accounting for completed requests
            InterlockedIncrement(&pTracker->CompletedRequests);
            InterlockedIncrement(&pTracker->ASyncRequests);
            if(!bResult) {
                error = GetLastError();
                if(error == ERROR_OPERATION_ABORTED) {
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: ASYNC REQUEST 0x%x (IOCODE %#.8x) CANCELED SUCCESSFULLY\n", GetCurrentThreadId(), request, request->iocode);
                    InterlockedIncrement(&pTracker->CanceledRequests);
                }
                else {
                    InterlockedIncrement(&pTracker->FailedRequests);
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: ASYNC REQUEST %#.8x (IOCODE %#.8x) FAILED WITH ERROR %#.8x\n", GetCurrentThreadId(), request, request->iocode, GetLastError());
                }
            }
            else {
                InterlockedIncrement(&pTracker->SuccessfulRequests);
                TPRINT(LEVEL_INFO_ALL, L"TID[%x]: ASYNC REQUEST %#.8x (IOCODE %#.8x) SUCCEEDED\n", GetCurrentThreadId(), request, request->iocode);
            }
            InterlockedDecrement(&pTracker->PendingRequests);
        }
        else {
            request = NULL;
        }

        // Keep firing until enough requests are pending or we are finishing
        while(!tbail) {
            // Fire IOCTL
            status = SendIoctl(hDev, &request, pAsync_config->ioctls, pAsync_config->count, pTracker);
            // If no request, internal error happened
            if(request) {
                InterlockedIncrement(&pTracker->SentRequests);
            }
            else{
                TPRINT(LEVEL_ERROR, L"TID[%x]: ERROR SENDING REQUEST\n", GetCurrentThreadId());
                break;
            }
            // Now process actual IO status
            if(status==PENDING) {
                // Accounting for pending requests
                InterlockedIncrement(&pTracker->PendingRequests);
                // Handle pending IRPs
                TPRINT(LEVEL_INFO_ALL, L"TID[%x]: REQUEST %x (IOCODE %#.8x) IS PENDING\n", GetCurrentThreadId(), request, request->iocode);
                // Cancel a portion of requests
                if((ULONG)(rand()%100)<cancelRate) {
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: SENDING A CANCEL FOR REQUEST %#.8x (IOCODE %#.8x)\n", GetCurrentThreadId(), request, request->iocode);
                    canceled = CancelIoEx(hDev, &request->overlp);
                    if(!canceled) {
                        TPRINT(LEVEL_INFO_ALL, L"TID[%x]: FAILED TO SEND A CANCEL FOR REQUEST %#.8x (IOCODE %#.8x), ERROR %#.8x\n", GetCurrentThreadId(), request, request->iocode, GetLastError());
                    }
                }

                // Loose request allocation limit enforcing (for example with the default values, the max will be between 57 and 64)
                // Only allocate additional requests if the pending limit has not been reached and all the allocated requests are already pending
                if((ULONG)pTracker->PendingRequests<=maxPending-startingNbThreads && pTracker->AllocatedRequests<=pTracker->PendingRequests) {
                    // if((ULONG)pTracker->AllocatedRequests < (ULONG)(MAX_REQUESTS-s_nbThreads)-(ULONG)pTracker->PendingRequests) {
                    request = NULL; // Create new request
                }
                else {
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: ENOUGH REQUESTS ALLOCATED (%d) FOR THE CURRENTLY PENDING NUMBER REQUESTS OF %d\n", GetCurrentThreadId(), pTracker->AllocatedRequests, pTracker->PendingRequests);
                    break;
                }

            }
            else {
                // Displaying synchronous completion result
                InterlockedIncrement(&pTracker->CompletedRequests);
                InterlockedIncrement(&pTracker->SynchronousRequests);
                if(status==SUCCESS){
                    InterlockedIncrement(&pTracker->SuccessfulRequests);
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: SYNC I/O PACKET %#.8x (IOCODE %#.8x) COMPLETED SUCCESSFULLY\n", GetCurrentThreadId(), request, request->iocode);
                }
                else {
                    InterlockedIncrement(&pTracker->FailedRequests);
                    TPRINT(LEVEL_INFO_ALL, L"TID[%x]: SYNC I/O PACKET %#.8x (IOCODE %#.8x) FAILED WITH ERROR %#.8x\n", GetCurrentThreadId(), request, request->iocode, GetLastError());
                }
            }
        } // while firing ioctl

        // Exiting
        if(tbail) {
            // Cleaning Last request before exiting
            if(request) {
                CleanupRequest(request);
                InterlockedDecrement(&pTracker->AllocatedRequests);
            }
            // CLEANING UP PENDING ASYNC REQUESTS IN A SINGLE THREAD
            if(!cleanup) {
                if(!InterlockedDecrement(&pAsync_config->currentNbThreads)) {
                    // IM THE LAST THREAD OUT, DO THE CLEANUP
                    cleanup = TRUE;
                }
            }
            TPRINT(LEVEL_INFO_ALL, L"TID[%x]: CURRENT NUMBER OF PENDING REQUESTS %u\n", GetCurrentThreadId(), pTracker->PendingRequests);
        }
    } while(!tbail || cleanup&&pTracker->PendingRequests);

    // Last thread exiting
    if(cleanup) {
        TPRINT(LEVEL_INFO, L"TID[%x]: CLEANUP THREAD EXITED\n", GetCurrentThreadId());
    }
    else {
        TPRINT(LEVEL_INFO_ALL, L"TID[%x]: WORKER THREAD EXITED\n", GetCurrentThreadId());
    }
    return SUCCESS;
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
UINT CreateThreads(UINT nbOfThreads, PHANDLE pWorkerThreads, PASYNC_CONFIG pAsync_config)
{
    UINT i=0;
    HANDLE hThread;

    do{
        hThread = CreateThread(NULL, 0, Iocallback, pAsync_config, 0, NULL);
        pWorkerThreads[i] = hThread;
        i++;
    }
    while(i<nbOfThreads && hThread);

    return i;
}

//DESCRIPTION:
// This function creates the completion port and the requested number of threads.
// If threads creation fails, the successfully created threads' handles are closed before returning.
//
//INPUT:
// pHandle - pointer to thread handles array
// nbOfThreads - the number of threads handles
//
//OUTPUT:
// None
//
VOID CloseThreadHandles(PHANDLE pHandle, SIZE_T nbThreads)
{
    UINT i;
    for(i=0; i<nbThreads; i++) {
        CloseHandle(pHandle[i]);
    }
    return;
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
INT InitializeThreadsAndCompletionPort(UINT nbOfThreads, PHANDLE pWorkerThreads, PASYNC_CONFIG pAsync_config)
{
    int status = SUCCESS;
    UINT nbOfThreadsCreated;

    pAsync_config->hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0);
    if(pAsync_config->hIocp) {
        nbOfThreadsCreated = CreateThreads(nbOfThreads, pWorkerThreads, pAsync_config);
        if(nbOfThreadsCreated != nbOfThreads) {
            CloseThreadHandles(pWorkerThreads, nbOfThreadsCreated);
            status = N_ERROR;
        }
    }
    else {
        // print error GetLastError()
        status = N_ERROR;
    }
    return status;
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
// pTracker - the statistics tracker pointer
//OUTPUT:
// TRUE for success
// FALSE for error
//
INT Asyncfuzzer(HANDLE hDev, PIOCTL_STORAGE pIOCTLStorage, DWORD dwIOCTLCount, UINT nbOfThreadsRequested, ULONG timeLimit, ULONG maxPending, ULONG cancelRate, PTRACKER pTracker)
{
    ASYNC_CONFIG async_config = {hDev, INVALID_HANDLE_VALUE, dwIOCTLCount, pIOCTLStorage, maxPending, cancelRate, nbOfThreadsRequested, nbOfThreadsRequested, pTracker};
    PHANDLE workerThreads;
    INT status=SUCCESS;
    DWORD waitResult;

    // Call init function to create the threads and the i/o completion port, initialize PRNG seed and critical section necessary for cleanup
    status = InitAsyncFuzzer(&workerThreads, &async_config);
    if(status==SUCCESS) {
        // Associate this dev handle to iocp
        CreateIoCompletionPort(hDev, async_config.hIocp, 0, 0);
        // Pass control to the iocp handler
        if(!PostQueuedCompletionStatus(async_config.hIocp, 0, 0, NULL)) {
            TPRINT(LEVEL_ERROR, L"Failed to post completion status to completion port\n");
            status = N_ERROR;
        }
        // Wait for ctrl-c or timout
        waitResult = WaitForSingleObject(s_bailEvent, timeLimit*1000);
        if(waitResult!=WAIT_FAILED) {
            // Send termination signal
            if(PostQueuedCompletionStatus(async_config.hIocp, 0, 0, SPECIAL_OVERLAPPED_BAIL_ALL)) {
                // Waiting until all threads exit and clean up done
                waitResult = WaitForMultipleObjects(async_config.startingNbThreads, workerThreads, TRUE, CLEANUP_TIMEOUT);
                if(waitResult!=WAIT_OBJECT_0) {
                    TPRINT(LEVEL_ERROR, L"Not all worker threads exited properly. Cleanup might not have been completed.\n");
                }
            }
            else{
                TPRINT(LEVEL_ERROR, L"Failed to send termination event to threads. Process may need to be forcefully terminated\n");
            }
        }
        else {
            TPRINT(LEVEL_ERROR, L"Failed wait on termination event.\n");
        }
        // Cleanup
        CloseHandle(async_config.hIocp);
        CloseThreadHandles(workerThreads, async_config.startingNbThreads);
        HeapFree(GetProcessHeap(), 0, workerThreads);
    }
    else {
        TPRINT(LEVEL_ERROR, L"ASYNC FUZZER INIT FAILED. ABORTING RUN.\n");
    }
    return status;
}


// RETURN VALUE: NbOfThreads created, or 0 if failure
INT InitAsyncFuzzer(PHANDLE *ppHandles, PASYNC_CONFIG pAsync_config)
{
    UINT nbThreadsValid=0;
    int status=N_ERROR;
    PHANDLE pWorkerThreads=NULL;
    UINT requestedNbOfThreads = pAsync_config->startingNbThreads;

    // Init termination event
    ResetEvent(s_bailEvent);
    // Init PRNG seed
    srand((UINT)0x9c3a168f^GetTickCount());
    // Get a valid nb of threads: MAX_THREADS if too big, twice the nb of procs if too small
    if(requestedNbOfThreads>MAX_THREADS) {
        nbThreadsValid = MAX_THREADS;
        TPRINT(LEVEL_WARNING, L"Nb of threads too big, using %d\n", MAX_THREADS);
    }
    else {
        nbThreadsValid = requestedNbOfThreads ? requestedNbOfThreads : GetNumberOfProcs()*2;
    }
    pWorkerThreads = (PHANDLE)HeapAlloc(GetProcessHeap(), 0, sizeof(HANDLE)*nbThreadsValid);
    if(pWorkerThreads) {
        pAsync_config->currentNbThreads = pAsync_config->startingNbThreads = nbThreadsValid;
        status = InitializeThreadsAndCompletionPort(nbThreadsValid, pWorkerThreads, pAsync_config);
        if(status==SUCCESS) {
            TPRINT(LEVEL_INFO, L"Threads and IOCP created successfully\n");
        }
        else {
            nbThreadsValid=0;
            TPRINT(LEVEL_ERROR, L"Failed to create Threads and IOCP\n");
        }
    }
    // Fill the config struct and the output pointer
    *ppHandles = pWorkerThreads;
    return status;
}
