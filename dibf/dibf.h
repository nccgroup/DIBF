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
    vector<DWORD> bannedErrors;
    map<DWORD, ULONG> returnMap;
    // Functions
    BOOL readAndValidateCommandLineUlong(LPTSTR, ULONG, ULONG, PULONG, BOOL);
    BOOL DoAllBruteForce(DWORD, DWORD, BOOL);
    BOOL BruteForceIOCTLs(HANDLE, DWORD, DWORD, BOOL);
    BOOL BruteForceBufferSizes(HANDLE);
    BOOL ReadBruteforceResult();
    BOOL WriteBruteforceResult();
    BOOL SmartBruteCheck(HANDLE, DWORD, DWORD, BOOL);
    BOOL IsBanned(DWORD);
    static BOOL __stdcall BruteforceCtrlHandler(DWORD);
    VOID FuzzIOCTLs(DWORD, ULONG, PULONG, ULONG, ULONG);
    VOID usage(void);
};
