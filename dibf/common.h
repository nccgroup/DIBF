#pragma once
// Disabling informational warning indicating automatic inlining
// http://msdn.microsoft.com/en-us/library/k402bt7y.aspx
#pragma warning(disable:4711)

#include "stdafx.h"

// #define DEBUG

// Printing macro (bad nico)
#define TPRINT(verbose, format, ...) \
    if ((LONG)verbose<=(LONG)g_verbose) { \
        _tprintf(format, __VA_ARGS__); \
    }

// Verbosity levels
#define VERBOSITY_DEFAULT 1
#define VERBOSITY_ERROR 1
#define VERBOSITY_INFO 2
#define VERBOSITY_ALL 3
#ifdef DEBUG
#define VERBOSITY_DEBUG 0
#else
#define VERBOSITY_DEBUG 4
#endif

// Ioctl guessing vars
#define START_IOCTL_VALUE 0x00100000
#define END_IOCTL_VALUE 0xffffffff
#define MAX_BUFSIZE 8192 // 8k
// Ioctl info storage
#define MAX_IOCTLS 512
#define DIBF_BF_LOG_FILE L"dibf-bf-results.txt"
// Fuzzing stages
#define DWORD_FUZZER 1
#define RANDOM_FUZZER 2
#define NP_FUZZER 4
// Async I/O statuses
#define DIBF_SUCCESS ((DWORD)1)
#define DIBF_PENDING ((DWORD)0)
#define DIBF_ERROR ((DWORD)-1)

class IoctlStorage
{
public:
    IoctlStorage();
    ~IoctlStorage();
private:
    class IoctlDef
    {
    public:
        DWORD dwIOCTL;
        DWORD dwLowerSize;
        DWORD dwUpperSize;
    };
public:
    IoctlDef *ioctls;
    ULONG count;
};

// Globals
extern ULONG g_verbose;

// Functions
VOID PrintVerboseError(ULONG, DWORD);