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
    DWORD GetIoCode() {return iocode;}
    VOID SetIoCode(DWORD iocode) {this->iocode=iocode;}
    virtual ~IoRequest();
    OVERLAPPED overlp;
    BOOL testSendForValidRequest(BOOL);
    VOID reset();
    DWORD sendAsync();
    BOOL allocBuffers(DWORD, DWORD);
    UCHAR *getInbuf();
private:
    static const DWORD invalidIoctlErrorCodes[];
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
    static BOOL isValid(DWORD);
};