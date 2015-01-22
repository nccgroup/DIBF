#pragma once

#include "stdafx.h"
#include "common.h"

class Dibf {
public:
    // Constructor & Destructor
    Dibf();
    ~Dibf();
    // Functions
    BOOL start(INT, _TCHAR**);
private:
    // Vars
    TCHAR pDeviceName[MAX_PATH];
    IoctlStorage IOCTLStorage;
    // Functions
    BOOL readAndValidateCommandLineUlong(LPTSTR, ULONG, ULONG, PULONG, BOOL);
    BOOL DoAllBruteForce(PTSTR, DWORD, DWORD, BOOL);
    BOOL BruteForceIOCTLs(HANDLE, DWORD, DWORD, BOOL);
    BOOL BruteForceBufferSizes(HANDLE);
    BOOL ReadBruteforceResult(TCHAR*, BOOL*, IoctlStorage*);
    BOOL WriteBruteforceResult(TCHAR*, IoctlStorage*);
    VOID FuzzIOCTLs(DWORD, ULONG, PULONG, ULONG, ULONG);
    VOID usage(void);
};
