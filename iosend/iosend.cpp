// iosend : Single IOCTL sending utility

#include "stdafx.h"

#define TPRINTF(format, ...) \
    _ftprintf(stderr, format, __VA_ARGS__)

PVOID MapInputFile(TCHAR* filepath)
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

int _tmain(int argc, _TCHAR* argv[])
{
    BOOL bResult;
    HANDLE hDev;
    DWORD iocode, inlen, outlen, bytesreturned, error;
    PVOID inbuf, outbuf;
    LPTSTR errormessage;
    TCHAR *stop;

    // Check # of args
    if(argc==6) {
        // Get params from command line
        iocode = _tcstoul(argv[2], &stop, 0);
        inlen = _tcstoul(argv[4], &stop, 0);
        outlen = _tcstoul(argv[5], &stop, 0);
        // Open device
        hDev = CreateFile(argv[1], MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if(hDev != INVALID_HANDLE_VALUE) {
            TPRINTF(L"Device file %s opened successfully\n", argv[1]);
            if(inlen) {
                inbuf = MapInputFile(argv[3]);
            }
            else {
                inbuf = NULL;
            }
            if(!inlen || inbuf) {
                // Naively allocating output buffer
                outbuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outlen);
                if(outbuf) {
                    // Sending
                    TPRINTF(L"SENDING IOCTL %#.8x\n", iocode);
                    bResult = DeviceIoControl(hDev, iocode, inbuf, inlen, outbuf, outlen, &bytesreturned, NULL);
                    // Display Result
                    if(bResult){
                        std::cout.write((const char*)outbuf, bytesreturned);
                        TPRINTF(L"IOCTL completed SUCCESSFULLY, returned %u bytes\n", bytesreturned);
                    }
                    else {
                        error = GetLastError();
                        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL); // Such an ugly function
                        TPRINTF(L"IOCTL FAILED with error %x: %s\n", error, errormessage);
                        LocalFree(errormessage);
                    }
                    HeapFree(GetProcessHeap(), 0, outbuf);
                }
                else {
                    TPRINTF(L"Allocation failure for outbuf size %d\n", outlen);
                }
                // Cleanup mapping
                if(inbuf) {
                    UnmapViewOfFile(inbuf);
                }
            }
            CloseHandle(hDev);
        }
        else {
            TPRINTF(L"Device file open failed with error %#x\n", GetLastError());
        }
    }
    else {
        TPRINTF(L"USAGE: %s [Device] [IOCODE] [InputBufFilePath] [InputLen] [OutputLen] > [Output file]\n", argv[0]);
        TPRINTF(L"Notes:\n");
        TPRINTF(L" - This utility prints error/status messages to stderr\n");
        TPRINTF(L" - Upon successful IOCTL, output data is written to stdout\n");
    }
    return 0;
}
