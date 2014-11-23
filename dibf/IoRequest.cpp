#include "stdafx.h"
#include "IoRequest.h"

// Statics initialization
const DWORD IoRequest::invalidIoctlErrorCodes[] = {
    ERROR_INVALID_FUNCTION,
    ERROR_NOT_SUPPORTED,
    ERROR_INVALID_PARAMETER,
    ERROR_NO_SYSTEM_RESOURCES,
    NULL
};

// Simple constructors
IoRequest::IoRequest(HANDLE hDev) : hDev(hDev), inBuf(NULL), outBuf(NULL), inSize(0), outSize(0)
{
    // TPRINT(VERBOSITY_INFO, L"TID[%x]: NEW REQUEST %#.8x ALLOCATED\n", GetCurrentThreadId(), this);
    ZeroMemory(&overlp, sizeof(overlp));
}

IoRequest::IoRequest(HANDLE hDev, DWORD code) : hDev(hDev), iocode(code), inBuf(NULL), outBuf(NULL), inSize(0), outSize(0)
{
    // TPRINT(VERBOSITY_INFO, L"TID[%x]: NEW REQUEST %#.8x ALLOCATED\n", GetCurrentThreadId(), this);
    ZeroMemory(&overlp, sizeof(overlp));
}

VOID IoRequest::reset()
{
    ZeroMemory(&overlp, sizeof(overlp));
    return;
}

IoRequest::~IoRequest()
{
    // TPRINT(VERBOSITY_ALL, L"TID[%x]: FREEING REQUEST %x\n", GetCurrentThreadId(), this);
    if(inBuf) {
        HeapFree(GetProcessHeap(), 0x0, inBuf);
    }
    if(outBuf) {
        HeapFree(GetProcessHeap(), 0x0, outBuf);
    }
    return;
}

UCHAR *IoRequest::getInbuf()
{
    return inBuf;
}

BOOL IoRequest::allocBuffers(DWORD inSize, DWORD outSize)
{
    BOOL bResult=TRUE;
    PUCHAR buf;

    // If input buffer is requested and size is different
    if(inSize!=this->inSize) {
        // Realloc should (right?) optimize quick return if the requested size is already allocated
        buf = inBuf ? (UCHAR*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, inBuf, inSize) : (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, inSize);
        if(buf) {
            this->inBuf = buf;
            this->inSize = inSize;
        }
        else {
            bResult = FALSE;
        }
    }
    if(outSize!=this->outSize && bResult) {
        // Realloc should (right?) optimize quick return if the requested size is already allocated
        buf = outBuf ? (UCHAR*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outBuf, outSize) : (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSize);
        if(buf) {
            this->outBuf = buf;
            this->outSize = outSize;
        }
        else {
            bResult = FALSE;
        }
    }
    return bResult;
}

BOOL IoRequest::sendRequest(BOOL async, PDWORD lastError)
{
    BOOL bResult;
    DWORD dwBytes;

    bResult = DeviceIoControl(hDev, iocode, inBuf, inSize, outBuf, outSize, &dwBytes, async ? &overlp : NULL);
    if(!bResult) {
        *lastError = GetLastError();
    }
    // Print result
    // TPRINT(VERBOSITY_ALL, L"IOCTL %#.8x returned ", iocode);
    // PrintVerboseError(VERBOSITY_ALL, *lastError);
    return bResult;
}


DWORD IoRequest::sendAsync()
{
    DWORD error, dwResult=DIBF_ERROR;

    if(sendRequest(TRUE, &error)) {
        dwResult=DIBF_SUCCESS;
    }
    else {
        if(ERROR_IO_PENDING==error) {
            dwResult=DIBF_PENDING;
        }
    }
    return dwResult;
}

BOOL IoRequest::isValid(DWORD error)
{
    BOOL bResult=TRUE;
    UINT i=0;

    while(bResult&&invalidIoctlErrorCodes[i]) {
        if(invalidIoctlErrorCodes[i]==error) {
            bResult = FALSE;
        }
        ++i;
    }
    return bResult;
}

// TODO: CHECK DEEP PROBING FEATURE WORKS AS EXPECTED
BOOL IoRequest::testSendForValidRequest(BOOL deep)
{
    BOOL bResult=FALSE;
    DWORD dwSize, lastError;

    // If deep, attempt inlen 0-256 otherwise just try inlen 32
    // outlen is always 256 (usually there's only an upper bound)
    for(dwSize=deep?0:DEEP_BF_MAX; !bResult&&dwSize<=DEEP_BF_MAX; dwSize+=4) {
        allocBuffers(dwSize, DEFAULT_OUTLEN);
        bResult = sendRequest(FALSE, &lastError) || isValid(lastError);
    }
    return bResult;
}
