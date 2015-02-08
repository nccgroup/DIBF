#include "stdafx.h"
#include "common.h"

// Class statics
ULONG g_verbose=VERBOSITY_ERROR; // VERBOSITY_DEFAULT is VERBOSITY_ERROR
#ifdef UNICODE
wstring_convert<std::codecvt_utf8<wchar_t>> tstring::converter;
#endif

VOID PrintVerboseError(ULONG verbosity, DWORD error)
{
    LPTSTR errormessage;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
    TPRINT(verbosity, _T("error %#.8x: %s\n"), error, errormessage);
    LocalFree(errormessage);
}
