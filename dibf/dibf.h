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
    HANDLE hDevice;
    IoctlStorage IOCTLStorage; //TODO: add size-returning functionality to ReadBruteforceResult to be able to only allocate on heap what's needed
    // Functions
    BOOL readAndValidateCommandLineUlong(LPTSTR, ULONG, ULONG, PULONG, BOOL);
    BOOL DoAllBruteForce(PTSTR, DWORD, DWORD, BOOL);
    BOOL BruteForceIOCTLs(DWORD, DWORD, BOOL);
    BOOL BruteForceBufferSizes();
    BOOL ReadBruteforceResult(TCHAR*, IoctlStorage*);
    BOOL WriteBruteforceResult(TCHAR*, IoctlStorage*);
    VOID FuzzIOCTLs(HANDLE, IoctlStorage*, DWORD, ULONG, PULONG, ULONG, ULONG);
    VOID usage(void);
};
