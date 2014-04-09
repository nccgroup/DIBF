#pragma once

#include "stdafx.h"
#include "common.h"

// General
#define SUCCESS 1
#define PENDING 0
#define N_ERROR -1
#define WAIT 1
#define SEND 0
// Sync fuzzing
#define INVALID_BUFFER_SIZE 0xFFFFFFFF
#define MAX_BF_BUFFER_SIZE 8192 //8k
#define DUMMY_SIZE 256
#define CONSECUTIVE_FAILURES 4096
// Processors / threads constants
#define WINDOWS_MAX_PROCS 64
#define MAX_THREADS 2*WINDOWS_MAX_PROCS
#define CLEANUP_TIMEOUT 10000 // 10s for threads to do cleanup
// Default Concurency constants
#define MAX_PENDING 64 // max number of concurrent requests pending
#define CANCEL_RATE 15 // percentage of pending I/O to issue a cancel for
// Special requests for async fuzzer
#define SPECIAL_OVERLAPPED_BAIL_ALL (LPOVERLAPPED)0xFFFFFFFF
#define SPECIAL_OVERLAPPED_BAIL (LPOVERLAPPED)0xFFFFFFFE

// typedefs
typedef struct _IOCTL_REQUEST
{
    DWORD iocode;
    UCHAR *FuzzBuf;
    UCHAR *OutBuf;
    DWORD inSize;
    DWORD outSize;
    DWORD bytesreturned;
    OVERLAPPED overlp;
} IOCTL_REQUEST, *PIOCTL_REQUEST;

typedef struct _ASYNC_CONFIG
{
    HANDLE hDev;
    HANDLE hIocp;
    DWORD count;
    PIOCTL_STORAGE ioctls;
    ULONG maxPending;
    ULONG cancelRate;
    UINT startingNbThreads;
    volatile UINT currentNbThreads;
    PTRACKER pTracker;
} ASYNC_CONFIG, *PASYNC_CONFIG;

typedef struct _SYNC_CONFIG
{
    HANDLE hDev;
    DWORD count;
    PIOCTL_STORAGE ioctls;
    volatile DWORD *terminate;
    PTRACKER pTracker;
} SYNC_CONFIG, *PSYNC_CONFIG;

BOOL InitializeFuzzersTermination();
BOOL __stdcall CtrlHandler(DWORD);
UINT GetNumberOfProcs();
INT InitializeThreadsAndCompletionPort(UINT, PHANDLE, PASYNC_CONFIG);
UINT CreateThreads(UINT, PHANDLE, PASYNC_CONFIG);
VOID CloseThreadHandles(PHANDLE, SIZE_T);
DWORD WINAPI RandomFuzzer(PVOID);
DWORD WINAPI SlidingDWORDFuzzer(PVOID);
VOID StartSyncFuzzer(LPTHREAD_START_ROUTINE , HANDLE , PIOCTL_STORAGE , DWORD, ULONG, PTRACKER);
DWORD WINAPI Iocallback(PVOID);
INT SendIoctl(HANDLE, PIOCTL_REQUEST*, PIOCTL_STORAGE, DWORD, PTRACKER);
INT Asyncfuzzer(HANDLE, PIOCTL_STORAGE, DWORD, UINT, ULONG, ULONG, ULONG, PTRACKER);
INT InitAsyncFuzzer(PHANDLE*, PASYNC_CONFIG);
PIOCTL_REQUEST createRequest(DWORD, DWORD, DWORD);
BOOL FixRequest(PIOCTL_REQUEST, DWORD, DWORD);
BOOL CleanupRequest(PIOCTL_REQUEST);
