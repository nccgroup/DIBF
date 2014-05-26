#include "stdafx.h"
#include "common.h"

// Globals
ULONG g_verbose=LEVEL_ERROR; // Default is LEVEL_ERROR

VOID PrintVerboseError(ULONG verbosity, DWORD error)
{
    LPTSTR errormessage;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
    TPRINT(verbosity, L"error %#.8x: %s\n", error, errormessage);
    LocalFree(errormessage);
}