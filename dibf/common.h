#pragma once
// Disabling informational warning indicating automatic inlining
// http://msdn.microsoft.com/en-us/library/k402bt7y.aspx
#pragma warning(disable:4711)

#include "stdafx.h"

// Printing macro (bad nico)
#define TPRINT(verbose, format, ...) \
    if ((LONG)verbose<=(LONG)g_verbose) { \
        _tprintf(format, __VA_ARGS__); \
    }
// Verbosity levels
#define LEVEL_ALWAYS_PRINT 0
#define LEVEL_ERROR 0
#define LEVEL_WARNING 1
#define LEVEL_INFO 2
#define LEVEL_INFO_ALL 3

typedef struct _IOCTL_STORAGE {
    DWORD dwIOCTL;
    DWORD dwLowerSize;
    DWORD dwUpperSize;
} IOCTL_STORAGE, *PIOCTL_STORAGE;

typedef struct _TRACKER{
    volatile long SentRequests;
    volatile long CompletedRequests;
    volatile long SynchronousRequests;
    volatile long ASyncRequests;
    volatile long SuccessfulRequests;
    volatile long FailedRequests;
    volatile long CanceledRequests;
    volatile long PendingRequests;
    volatile long AllocatedRequests;
} TRACKER, *PTRACKER;

// Globals
extern ULONG g_verbose;

// Functions
VOID PrintVerboseError(ULONG, DWORD);