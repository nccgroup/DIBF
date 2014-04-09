#pragma once

#include "stdafx.h"
#include "common.h"

// Ioctl guessing vars
#define START_IOCTL_VALUE 0x00100000
#define END_IOCTL_VALUE 0xffffffff
#define MAX_IOCTLS 512
#define DEEP_BF_MAX 32
#define DIBF_BF_LOG_FILE L"dibf-bf-results.txt"
#define RANDOM_FUZZER 1
#define DWORD_FUZZER 2
#define ASYNC_FUZZER 4

// Function definitions
BOOL CallDeviceIoControl(HANDLE, DWORD, BOOL);
DWORD BruteForceIOCTLs(HANDLE, PIOCTL_STORAGE, DWORD, DWORD, BOOL);
BOOL BruteForceBufferSizes(HANDLE, PIOCTL_STORAGE);
BOOL ReadBruteforceResult(TCHAR*, PIOCTL_STORAGE, PDWORD);
BOOL WriteBruteforceResult(TCHAR*, PIOCTL_STORAGE);
VOID FuzzIOCTLs(HANDLE, PIOCTL_STORAGE, DWORD, DWORD, ULONG, PULONG, ULONG, ULONG);
VOID usage(void);
VOID printTracker(PTRACKER);
