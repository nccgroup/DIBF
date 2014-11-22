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

// Ioctl guessing vars
#define START_IOCTL_VALUE 0x00100000
#define END_IOCTL_VALUE 0xffffffff
#define MAX_IOCTLS 512
#define DEEP_BF_MAX 32
#define DIBF_BF_LOG_FILE L"dibf-bf-results.txt"
#define RANDOM_FUZZER 1
#define DWORD_FUZZER 2
#define ASYNC_FUZZER 4
#define DIBF_SUCCESS 1
#define DIBF_PENDING 0
#define DIBF_ERROR -1

class IoctlStorage
{
public:
    IoctlStorage();
    virtual ~IoctlStorage();
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