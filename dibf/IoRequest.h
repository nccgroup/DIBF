#pragma once
#include "stdafx.h"
#include "common.h"

#define MAX_IOCTLS 512
#define DEEP_BF_MAX 32
#define DEFAULT_OUTLEN 256

class IoRequest
{
public:
    IoRequest();
    IoRequest(HANDLE);
    IoRequest(HANDLE, DWORD);
    ~IoRequest();
    DWORD GetIoCode() {return iocode;}
    VOID SetIoCode(DWORD iocode) {this->iocode=iocode;}
    OVERLAPPED overlp;
    BOOL testSendForValidRequest(BOOL);
    BOOL testSendForValidBufferSize(DWORD);
    VOID reset();
    DWORD sendAsync();
    BOOL allocBuffers(DWORD, DWORD);
    UCHAR *getInbuf();
private:
    // Static arrays of known interesting errors
    static const DWORD invalidIoctlErrorCodes[];
    static const DWORD invalidBufSizeErrorCodes[];
    // Members
    HANDLE hDev;
    DWORD iocode;
    UCHAR *inBuf;
    UCHAR *outBuf;
    DWORD inSize;
    DWORD outSize;
    DWORD bytesreturned;
    // Functions
    BOOL sendRequest(BOOL, PDWORD);
};