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
    tstring deviceName;
    BOOL gotDeviceName;
    vector<IoctlDef> ioctls;
    // Functions
    BOOL readAndValidateCommandLineUlong(LPTSTR, ULONG, ULONG, PULONG, BOOL);
    BOOL DoAllBruteForce(DWORD, DWORD, BOOL);
    BOOL BruteForceIOCTLs(HANDLE, DWORD, DWORD, BOOL);
    BOOL BruteForceBufferSizes(HANDLE);
    BOOL ReadBruteforceResult();
    BOOL WriteBruteforceResult();
    VOID FuzzIOCTLs(DWORD, ULONG, PULONG, ULONG, ULONG);
    VOID usage(void);
};
