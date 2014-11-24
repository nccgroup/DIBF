#include "stdafx.h"
#include "common.h"

// Globals
ULONG g_verbose=VERBOSITY_ERROR; // VERBOSITY_DEFAULT is VERBOSITY_ERROR

IoctlStorage::IoctlStorage()
{
    TPRINT(VERBOSITY_DEBUG, L"IoctlStorage constructor\n");
    ioctls = (IoctlDef*)HeapAlloc(GetProcessHeap(), 0, sizeof(IoctlDef)*MAX_IOCTLS);
}

IoctlStorage::~IoctlStorage()
{
    TPRINT(VERBOSITY_DEBUG, L"IoctlStorage destructor\n");
    HeapFree(GetProcessHeap(), 0, ioctls);
}

VOID PrintVerboseError(ULONG verbosity, DWORD error)
{
    LPTSTR errormessage;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
    TPRINT(verbosity, L"error %#.8x: %s\n", error, errormessage);
    LocalFree(errormessage);
}