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
#define END_IOCTL_VALUE 0xfffffffe
#define MAX_BUFSIZE 8192 // 8k
// Smart bruteforcing error code checks
#define TOTAL_ERROR_CHECKS 10000
#define BAN_THRESHOLD 100
// Ioctl info storage
#define MAX_IOCTLS 512
// Fuzzing stages
#define DWORD_FUZZER 1
#define RANDOM_FUZZER 2
#define NP_FUZZER 4
// Async I/O statuses
#define DIBF_SUCCESS ((DWORD)1)
#define DIBF_PENDING ((DWORD)0)
#define DIBF_ERROR ((DWORD)-1)

// Workaround for c++/TCHAR
#ifdef UNICODE
class tstring
{
private:
    static wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    string str;
    wstring ws;
public:
    tstring() {} // default constructor
    tstring(LPCTSTR s) : str(string(converter.to_bytes(s))) {}
    bool empty() { return str.empty(); }
    tstring &append(tstring other) { str.append(other.str); return *this; }
    operator string() { return str; }
    operator LPCTSTR() { ws=wstring(converter.from_bytes(str)); return ws.c_str(); }
    bool operator==(const tstring &other) const { return (this->str==other.str); }
    bool operator!=(const tstring &other) const { return (this->str!=other.str); }
};
#else
class tstring
{
private:
     string str;
public:
    tstring() {} // default constructor
    tstring(LPCTSTR s) : str((LPCSTR)s) {}
    bool empty() { return str.empty(); }
    tstring &append(tstring other) { str.append(other.str); return *this; }
    operator string() { return str; }
    operator LPCTSTR() { return (LPCTSTR)str.c_str(); }
    bool operator==(const tstring &other) const { return (this->str==other.str); }
    bool operator!=(const tstring &other) const { return (this->str!=other.str); }
};
#endif

// Ioctl definition storage
struct IoctlDef
{
    IoctlDef() : dwIOCTL(0), dwLowerSize(0), dwUpperSize(0) {}
    DWORD dwIOCTL;
    DWORD dwLowerSize;
    DWORD dwUpperSize;
};

// Globals
extern ULONG g_verbose;

// Functions
VOID PrintVerboseError(ULONG, DWORD);

// Quick template to find error code in regular static c arrays
template<size_t SIZE>
static BOOL IsInCArray(const DWORD (&table)[SIZE], DWORD error)
{
    BOOL bResult=FALSE;

    if(find(begin(table), end(table), error)!= end(table)) {
        bResult = TRUE;
    }
    return bResult;
}
