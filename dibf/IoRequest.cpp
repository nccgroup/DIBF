#include "stdafx.h"
#include "IoRequest.h"

// Statics initialization
const DWORD IoRequest::invalidIoctlErrorCodes[] = {
    ERROR_INVALID_FUNCTION,
    ERROR_NOT_SUPPORTED,
    ERROR_INVALID_PARAMETER,
    ERROR_NO_SYSTEM_RESOURCES
};
const DWORD IoRequest::invalidBufSizeErrorCodes[] = {
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_BAD_LENGTH,
};

// Quick template to find error code in regular static c arrays
template<size_t SIZE>
static BOOL IsInCArray(const DWORD (&table)[SIZE], DWORD error)
{
    BOOL bResult=FALSE;

    if(std::find(std::begin(table), std::end(table), error) != std::end(table)) {
        bResult = TRUE;
    }
    return bResult;
}

#define IsValidCode(ERROR) (!IsInCArray<_countof(invalidIoctlErrorCodes)>(invalidIoctlErrorCodes, ERROR))
#define IsValidSize(ERROR) (!IsInCArray<_countof(invalidBufSizeErrorCodes)>(invalidBufSizeErrorCodes, ERROR))

// Simple constructors
IoRequest::IoRequest(HANDLE hDev) : hDev(hDev), inBuf(NULL), outBuf(NULL), inSize(0), outSize(0)
{
    ZeroMemory(&overlp, sizeof(overlp));
}

IoRequest::IoRequest(HANDLE hDev, DWORD code) : hDev(hDev), iocode(code), inBuf(NULL), outBuf(NULL), inSize(0), outSize(0)
{
    ZeroMemory(&overlp, sizeof(overlp));
}

VOID IoRequest::reset()
{
    ZeroMemory(&overlp, sizeof(overlp));
    return;
}

IoRequest::~IoRequest()
{
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
        buf = inBuf ? (UCHAR*)HeapReAlloc(GetProcessHeap(), 0, inBuf, inSize) : (UCHAR*)HeapAlloc(GetProcessHeap(), 0, inSize);
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
        buf = outBuf ? (UCHAR*)HeapReAlloc(GetProcessHeap(), 0, outBuf, outSize) : (UCHAR*)HeapAlloc(GetProcessHeap(), 0, outSize);
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

VOID IoRequest::assignBuffers(PUCHAR inBuf, PUCHAR outBuf)
{
    if(inBuf) {
        if(inSize) {
            HeapFree(GetProcessHeap(), 0, this->inBuf);
        }
        this->inBuf = inBuf;
    }
    if(outBuf) {
        if(outSize) {
            HeapFree(GetProcessHeap(), 0, this->outBuf);
        }
        this->outBuf = outBuf;
    }
    return;
}

BOOL IoRequest::sendRequest(BOOL async, PDWORD lastError)
{
    BOOL bResult;
    DWORD dwBytes;

    bResult = DeviceIoControl(hDev, iocode, inBuf, inSize, outBuf, outSize, &dwBytes, async ? &overlp : NULL);
    if(!bResult) {
        *lastError = GetLastError();
    }
    return bResult;
}

BOOL IoRequest::sendSync()
{
    BOOL bResult=FALSE;
    DWORD error;

    if(sendRequest(FALSE, &error)) {
        bResult=TRUE;
    }
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

BOOL IoRequest::testSendForValidRequest(BOOL deep)
{
    BOOL bResult=FALSE;
    DWORD dwSize, lastError=0;
    LPTSTR errormessage;

    // If deep, attempt inlen 0-256 otherwise just try inlen 32
    // outlen is always 256 (usually there's only an upper bound)
    for(dwSize=deep?0:DEEP_BF_MAX; !bResult&&dwSize<=DEEP_BF_MAX; dwSize+=4) {
        bResult = allocBuffers(dwSize, DEFAULT_OUTLEN);
        if(bResult) {
            bResult = sendRequest(FALSE, &lastError) || IsValidCode(lastError);
        }
    }
    // Print return code indicating valid IOCTL code
    if(bResult) {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, lastError, 0, (LPTSTR)&errormessage, 4, NULL);
        if(errormessage) {
            TPRINT(VERBOSITY_INFO, L"Found IOCTL: %#.8x failed with error %#.8x - %s", iocode, lastError, errormessage);
            LocalFree(errormessage);
        }
        else {
            TPRINT(VERBOSITY_INFO, L"Found IOCTL: %#.8x failed with error %#.8x\n", iocode, lastError);
        }
    }
    return bResult;
}

BOOL IoRequest::testSendForValidBufferSize(DWORD testSize)
{
    BOOL bResult=FALSE;
    DWORD lastError;
    LPTSTR errormessage;

    if(allocBuffers(testSize, DEFAULT_OUTLEN)) {
        bResult = sendRequest(FALSE, &lastError) || IsValidSize(lastError);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, lastError, 0, (LPTSTR)&errormessage, 4, NULL);
    } // if allocbuffers
    return bResult;
}

BOOL IoRequest::fuzz(FuzzingProvider* fp, std::mt19937* prng)
{
    BOOL bResult=FALSE;
    PUCHAR newBuf;

    bResult = fp->GetRandomIoctlAndBuffer(&iocode, &newBuf, &inSize, prng);
    if(bResult) {
        assignBuffers(newBuf, 0);
    }
    return bResult;
}