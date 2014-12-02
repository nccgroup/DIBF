// iosend : Single IOCTL sending utility

#include "stdafx.h"

#define TPRINTF(format, ...) \
    _ftprintf(stderr, format, __VA_ARGS__)

VOID usage(LPTSTR path)
{
    TCHAR exename[_MAX_FNAME];

    _tsplitpath_s(path, (LPTSTR)NULL, 0, (LPTSTR)NULL, 0, (LPTSTR)&exename, _MAX_FNAME, (LPTSTR)NULL, 0);
    TPRINTF(L"%s [Device] [IOCODE] [InputBufFilePath|InputAdress] [InputLen] [[OutputAddress]] [OutputLen] > [Output file]\n", exename);
    TPRINTF(L"Notes:\n");
    TPRINTF(L" - This utility prints error/status messages to stderr\n");
    TPRINTF(L" - Input can be provided as an arbitrary address or a file name\n");
    TPRINTF(L" - An output buffer is allocated and its contents eventually written to stdout unless the optional OutputAddress parameter is provided\n");
    return;
}

PVOID mapInputFile(TCHAR* filepath)
{
    HANDLE hFile, hMap;
    PVOID pView=NULL;

    // Open file
    hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile!=INVALID_HANDLE_VALUE) {
        // Create the file mapping object
        hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if(hMap) {
            pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
            if(pView) {
                TPRINTF(L"Successfully mapped view of file %s as input\n", filepath);
            }
            else {
                TPRINTF(L"Failed to map view of file %s with error %x\n", filepath, GetLastError());
            }
            CloseHandle(hMap);
        }
        else {
            TPRINTF(L"Failed to create file mapping for %s with error %x\n", filepath, GetLastError());
        }
        CloseHandle(hFile);
    }
    else {
        TPRINTF(L"Failed to open file %s with error %#.8x\n", filepath, GetLastError());
    }
    return pView;
}

BOOL strToPtr(LPCTSTR str, PVOID *ptr)
{
    TCHAR *stop;
#if _WIN32
    *ptr = (PVOID)_tcstoul(str, &stop, 0);
#else
    *ptr = (PVOID)_tcstoi64(str, &stop, 0);
#endif
    return (ptr&&*stop==L'\0');
}

BOOL sendIoctl(LPCTSTR deviceName, DWORD iocode, LPTSTR inputNameOrAddress, DWORD inlen, PVOID outbuf, DWORD outlen, PDWORD bytesreturned, PDWORD error)
{
    BOOL bResult, bSent=FALSE, bAddress=FALSE;
    HANDLE hDev;
    PVOID inbuf;

    // Open device
    hDev = CreateFile(deviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hDev!=INVALID_HANDLE_VALUE) {
        TPRINTF(L"Device file %s opened successfully\n", deviceName);
        // Attempt to parse argument as an address
        bAddress = strToPtr(inputNameOrAddress, &inbuf);
        // Passed argument does not parse as an address
        if(!bAddress) {
            // Try using the parameter as a file name to map
            inbuf = mapInputFile(inputNameOrAddress);
        }
        // If we have an input address straight from command line,
        // or the address of a successfully mapped file
        if(bAddress||inbuf) {
            // Sending
            TPRINTF(L"Sending ioctl %#.8x\n", iocode);
            bResult = DeviceIoControl(hDev, iocode, inbuf, inlen, outbuf, outlen, bytesreturned, NULL);
            *error = bResult?ERROR_SUCCESS:GetLastError();
            bSent = TRUE;
            // Cleanup mapping
            if(!bAddress&&inbuf) {
                UnmapViewOfFile(inbuf);
            }
        }
        CloseHandle(hDev);
    }
    else {
        TPRINTF(L"Device file open failed with error %#x\n", GetLastError());
    }
    return bSent;
}

INT _tmain(INT argc, _TCHAR* argv[])
{
    BOOL bSent=FALSE;
    PVOID outbuf;
    DWORD outlen, bytesreturned=0, error=ERROR_SUCCESS;
    TCHAR *stop;
    LPTSTR errormessage;

    // Check # of args
    switch(argc) {
    // Usage 1
    case 6:
        // Get output buffer length from command line and allocate it
        outlen = _tcstoul(argv[5], &stop, 0);
        // Naively allocating output buffer
        outbuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outlen);
        if(outbuf) {
            bSent = sendIoctl(argv[1], _tcstoul(argv[2], &stop, 0), argv[3], _tcstoul(argv[4], &stop, 0), outbuf, outlen, &bytesreturned, &error);
            // Redirect output to stdout
            if(bSent && error==ERROR_SUCCESS) {
                std::cout.write((const char*)outbuf, bytesreturned);
            }
            HeapFree(GetProcessHeap(), 0, outbuf);
        }
        else {
            TPRINTF(L"Allocation failure for outbuf size %d\n", outlen);
        }
        break;
    // Usage 2
    case 7:
        // Pass arbitrary command line parameters as outbuf address and length
        outlen = _tcstoul(argv[6], &stop, 0);
        if(strToPtr(argv[5], &outbuf)) {
            bSent = sendIoctl(argv[1], _tcstoul(argv[2], &stop, 0), argv[3], _tcstoul(argv[4], &stop, 0), outbuf, outlen, &bytesreturned, &error);
        }
        else {
            TPRINTF(L"Failed to parse output address \"%s\"\n", argv[5]);
            usage(argv[0]);
        }
        break;
    default:
        usage(argv[0]);
        break;
    }
    // Display Result
    if(bSent) {
        if(error==ERROR_SUCCESS) {
            TPRINTF(L"IOCTL completed SUCCESSFULLY, returned %u bytes\n", bytesreturned);
        }
        else {
            // Verbose error
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
            TPRINTF(L"IOCTL FAILED with error %x: %s\n", error, errormessage);
            LocalFree(errormessage);
        }
    }
    return 0;
}
