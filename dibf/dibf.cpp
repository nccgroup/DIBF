/***********************************************************************************
* dib.cpp : Defines the entry point for the console application.                   *
*                                                                                  *
* TODO:                                                                            *
* - Alter code to be resilient against IOCTLs that locks                           *
* - Minimize bruteforce space <- Probably not doable                               *
* - Add functionality to write found IOCTLs and sizes into a file                  *
*     => start / restart fuzzer without doing a bruteforce                         *
************************************************************************************/

#include "stdafx.h"
#include "dibf.h"
#include "Fuzzers.h"

//DESCRIPTION:
// This function reads a ULONG in decimal or hex from a string and eventually verifies it is within bounds
//
//INPUT:
// str - the string to parse
// lowerBound - the lower bound (inclusive)
// upperBound - the lower bound (inclusive)
// out - the resulting ULONG
// check - determines whether to bound check or not
//
//OUTPUT:
// TRUE on success
// FALSE on failure
//
BOOL readAndValidateCommandLineUlong(LPTSTR str, ULONG lowerBound, ULONG upperBound, PULONG out, BOOL check)
{
    BOOL bResult=FALSE;
    TCHAR *pEnd;
    ULONG ret;

    // let _tcstoul handle the base
    ret = _tcstoul(str, &pEnd, 0);
    if( (*pEnd==L'\0') && (!check||(ret>=lowerBound&&ret<=upperBound))) {
        bResult=TRUE;
        *out = ret;
    }
    return bResult;
}


//DESCRIPTION:
// This function prints the RUN STARTED/RUN ENDED date & time string
//
//INPUT:
// ended - boolean controlling whether to print "RUN ENDED" OR "RUN STARTED"
//
//OUTPUT:
// None
//
VOID printDateTime(BOOL ended)
{
    TCHAR timestr[64];
    TCHAR datestr[64];
    LPTSTR fmt = ended ? L"RUN ENDED: %s %s\n" : L"RUN STARTED: %s %s\n";

    // Print date & time
    if(GetDateFormat(LOCALE_USER_DEFAULT, 0, NULL, NULL, datestr, 32) && GetTimeFormat(LOCALE_USER_DEFAULT, TIME_NOSECONDS, NULL, NULL, timestr, 32)) {
        TPRINT(LEVEL_ALWAYS_PRINT, fmt, datestr, timestr);
    }
    else {
        TPRINT(LEVEL_ALWAYS_PRINT, L"TIME NOT AVAILABLE\n");
    }
    return;
}

//DESCRIPTION:
// This function prints the cummulative tracked statitists
//
//INPUT:
// pTracker - Pointer to the tracker struct
//
//OUTPUT:
// None
VOID printTracker(PTRACKER pTracker)
{
    // Wait for all the volatile writes to go through
    MemoryBarrier();
    // clean print
    fflush(stdout);
    // Print summary
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Sent Requests : %d\n", pTracker->SentRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"Completed Requests : %d (%d sync, %d async)\n", pTracker->CompletedRequests, pTracker->SynchronousRequests, pTracker->ASyncRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"SuccessfulRequests : %d\n", pTracker->SuccessfulRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"FailedRequests : %d\n", pTracker->FailedRequests);
    TPRINT(LEVEL_ALWAYS_PRINT, L"CanceledRequests : %d\n", pTracker->CanceledRequests);
    TPRINT(LEVEL_INFO_ALL, L"----\n");
    TPRINT(LEVEL_INFO_ALL, L"Consistent Results: %s\n", pTracker->SuccessfulRequests
        +pTracker->FailedRequests
        +pTracker->CanceledRequests
        == pTracker->CompletedRequests ? L"YES" : L"NO (it's ok)");
    TPRINT(LEVEL_INFO_ALL, L"Cleanup completed: %s\n", !pTracker->AllocatedRequests ? L"YES" : L"NO (it's ok)");
    TPRINT(LEVEL_INFO_ALL, L"----\n");
    printDateTime(TRUE);
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n\n");
    return;
}

HANDLE DoAllBruteForce(PTSTR pDeviceName, DWORD dwIOCTLStart, DWORD dwIOCTLEnd, PIOCTL_STORAGE pIOCTLStorage, PDWORD pdwIOCTLCount, BOOL deep)
{
    HANDLE hDevice;

    hDevice = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(hDevice!=INVALID_HANDLE_VALUE) {
        //Bruteforce IOCTLs
        TPRINT(LEVEL_ALWAYS_PRINT, L"<< Bruteforcing IOCTLs >>\n");
        *pdwIOCTLCount = BruteForceIOCTLs(hDevice, pIOCTLStorage, dwIOCTLStart, dwIOCTLEnd, deep);
        if(pIOCTLStorage[0].dwIOCTL!=0) {
            TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n\n");
            TPRINT(LEVEL_INFO, L"Bruteforcing buffer sizes\n");
            if(BruteForceBufferSizes(hDevice, pIOCTLStorage)) {
                TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------\n\n");
                TPRINT(LEVEL_INFO, L"Writing bruteforce results to file\n");
                WriteBruteforceResult(pDeviceName, pIOCTLStorage);
            }
        }
        else {
            TPRINT(LEVEL_ERROR, L"Unable to find any valid IOCTLs, exiting...\n");
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }
    else {
        TPRINT(LEVEL_ERROR, L"Unable to open device %s, error %#.8x\n", pDeviceName, GetLastError());
    }
    return hDevice;
}

//DESCRIPTION:
// main
//
//INPUT:
// command line
//
//OUTPUT:
// returns 0
//
int _tmain(int argc, _TCHAR* argv[])
{
    int i;
    TCHAR pDeviceName[MAX_PATH];
    HANDLE hDevice=INVALID_HANDLE_VALUE;
    IOCTL_STORAGE pIOCTLStorage[MAX_IOCTLS]={0}; //TODO: add size-returning functionality to ReadBruteforceResult to be able to only allocate on heap what's needed
    BOOL bDeepBruteForce=FALSE, bResultsFromFile=FALSE, validUsage=TRUE, bIgnoreFile=FALSE, gotDeviceName=FALSE;
    DWORD dwIOCTLStart=START_IOCTL_VALUE, dwIOCTLEnd=END_IOCTL_VALUE, dwFuzzStage=0xf, dwIOCTLCount=0;
    ULONG maxThreads=0, timeLimits[3]={INFINITE, INFINITE,INFINITE}, cancelRate=CANCEL_RATE, maxPending=MAX_PENDING;

    for(i=1; validUsage && i<argc; i++) {
        if(argv[i][0] == L'-') {
            switch(argv[i][1]) {
            case L'd':
            case L'D':
                bDeepBruteForce = TRUE;
                break;
            case L'v':
            case L'V':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 3, &g_verbose, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Invalid verbosity level or bad syntax.\n");
                    validUsage = FALSE;
                }
                break;
            case L's':
            case L'S':
                if((i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLStart, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'e':
            case L'E':
                if(!bResultsFromFile && (i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLEnd, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L't':
            case L'T':
                if(i<argc-1 && 3==_stscanf_s(argv[i+1], L"%u,%u,%u", &timeLimits[0], &timeLimits[1], &timeLimits[2]))
                    {
                        i++;
                    }
                    else {
                        TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                        validUsage = FALSE;
                    }
                break;
            case L'a':
            case L'A':
                // Thread max will be handled later
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &maxThreads, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'p':
            case L'P':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &maxPending, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'c':
            case L'C':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 100, &cancelRate, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'f':
            case L'F':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 7, &dwFuzzStage, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(LEVEL_ALWAYS_PRINT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'i':
            case L'I':
                bIgnoreFile = TRUE;
                break;
            case L'h':
            case L'H':
                validUsage = FALSE;
                break;
            default:
                validUsage = FALSE;
                break;
            }
        }
        else {
            // This is the last parameter
            if(i==argc-1) {
                _tcsncpy_s(pDeviceName, MAX_PATH, argv[i], _TRUNCATE);
                gotDeviceName = TRUE;
            }
            else {
                validUsage = FALSE;
            }
        }
    }
    // Unless -i
    if(!bIgnoreFile) {
    // Attempt to read file
        bResultsFromFile = ReadBruteforceResult(pDeviceName, pIOCTLStorage, &dwIOCTLCount);
    }
    // usage verified and device name from file or commandline
    if(validUsage && (bResultsFromFile || gotDeviceName)) {
        // Open the device based on the file name read from file
        if(bResultsFromFile) {
            hDevice = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
            if(hDevice==INVALID_HANDLE_VALUE) {
                TPRINT(LEVEL_ERROR, L"Error opening device %s, error %d\n", pDeviceName, GetLastError());
            }
        }
        // Open the device based on the file name passed from params, fuzz the IOCTLs and return the device handle
        else {
            hDevice = DoAllBruteForce(pDeviceName, dwIOCTLStart, dwIOCTLEnd, pIOCTLStorage, &dwIOCTLCount, bDeepBruteForce);
        }
        // Got a valid handle and valid IOCTLS to fuzz, onto actual fuzzing
        if(hDevice!=INVALID_HANDLE_VALUE) {
            TPRINT(LEVEL_INFO, L"Fuzzing %d IOCTLs on device %s\n", dwIOCTLCount, pDeviceName);
            FuzzIOCTLs(hDevice, pIOCTLStorage, dwFuzzStage, dwIOCTLCount, maxThreads, timeLimits, maxPending, cancelRate);
            // Cleanup
            CloseHandle(hDevice);
        }
    } // if validUsage
    else {
        usage();
    }
    return 0;
}

//DESCRIPTION:
// This function fills the pIOCTLStorage array with valid IOCTLs found by CallDeviceIoControl().
//
//INPUT:
// hDevice - Handle to device object.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
// bDeepBruteForce - Boolean telling us if we are doing the deep bruteforce or not.
// bVerbose - Boolean telling us if we want verbose output or not.
//
//OUTPUT:
// Last index into pIOCTLStorage array (count of found IOCTLs - 1).
//
DWORD BruteForceIOCTLs(HANDLE hDevice, PIOCTL_STORAGE pIOCTLStorage, DWORD dwIOCTLStart, DWORD dwIOCTLEnd, BOOL bDeepBruteForce)
{
    DWORD dwIOCTL=dwIOCTLStart, dwIOCTLIndex=0;

    while(dwIOCTL<dwIOCTLEnd) {
        if(CallDeviceIoControl(hDevice, dwIOCTL, bDeepBruteForce)) {
            if(dwIOCTLIndex<MAX_IOCTLS) {
                TPRINT(LEVEL_INFO, L" Found IOCTL %#.8x\n",dwIOCTL);
                pIOCTLStorage[dwIOCTLIndex++].dwIOCTL = dwIOCTL;
            }
            else {
                TPRINT(LEVEL_ERROR, L" Found IOCTL but out of storage space, stopping bruteforce\n");
                return MAX_IOCTLS;
            }
        }
        if(dwIOCTL % 0x01000000 == 0) {
            TPRINT(LEVEL_INFO, L"%#.8x\n", dwIOCTL);
        }
        dwIOCTL++;
    }
    return dwIOCTLIndex;
}

//DESCRIPTION:
// Calls DeviceIoControl to determine if an IOCTL value is valid or not. If DeviceIoControl() returns TRUE
// we know the IOCTL is valid. If DeviceIoControl() returns false, the IOCTL is though as being valid if
// the error code is not ERROR_INVALID_FUNCTION or ERROR_NOT_SUPPORTED.
// Doing a deep bruteforce calls DeviceIoControl() with several sizes between 0 and 32.
//
//INPUT:
// hDevice - Handle to device object.
// dwIOCTL - IOCTL value to test.
// bDeepBruteForce - Boolean telling us if we are doing the deep bruteforce or not. Deep BF means we call
// DeviceIoControl with several different sizes to increase our chances of getting past
// very strict size checks happening before the dispatch function.
//
//OUTPUT:
// Boolean telling us if the IOCTL was valid or not.
//
BOOL __inline CallDeviceIoControl(HANDLE hDevice, DWORD dwIOCTL, BOOL bDeepBruteForce)
{
    DWORD dwBytesReturned,dwError,dwSize;
    BYTE bDummyBuffer[DUMMY_SIZE] = {};

    if(bDeepBruteForce) {
        for(dwSize=0; dwSize<=DEEP_BF_MAX; dwSize+=4) {
            if(DeviceIoControl(hDevice, dwIOCTL, bDummyBuffer, dwSize, bDummyBuffer, DUMMY_SIZE, &dwBytesReturned, NULL)) {
                return TRUE;
            }
            else {
                dwError = GetLastError();
                if((dwError!=ERROR_INVALID_FUNCTION) && (dwError!=ERROR_NOT_SUPPORTED)) {
                    return TRUE;
                }
            }
        }
    }
    if(DeviceIoControl(hDevice, dwIOCTL, bDummyBuffer, DUMMY_SIZE, bDummyBuffer, DUMMY_SIZE, &dwBytesReturned, NULL)) {
        return TRUE;
    }
    else {
        dwError = GetLastError();
        if((dwError != ERROR_INVALID_FUNCTION) && (dwError != ERROR_NOT_SUPPORTED)) {
            return TRUE;
        }
    }
    return FALSE;
}

//DESCRIPTION:
// Tries to determine valid buffer size range (lower / upper) by calling DeviceIoControl() and looking for
// ERROR_INVALID_PARAMETER error messages. Lower edge is found by starting from 0 and increasing the size,
// while the upper edge is found by starting at the MAX and decreasing the size. Populates the pIOCTLStorage
// array with the found size edges.
//
//INPUT:
// hDevice - Handle to device object.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
//
//OUTPUT:
// None.
//
BOOL BruteForceBufferSizes(HANDLE hDevice, PIOCTL_STORAGE pIOCTLStorage)
{
    BOOL bResult=TRUE;
    PBYTE pDummyBuffer=NULL;
    DWORD i=0, dwCurrentSize, dwBytesReturned;

    pDummyBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BF_BUFFER_SIZE);
    if(pDummyBuffer) {
        while((i<MAX_IOCTLS) && (pIOCTLStorage[i].dwIOCTL!=0)) {
            TPRINT(LEVEL_INFO, L" Working on IOCTL %#.8x\n", pIOCTLStorage[i].dwIOCTL);
            //find lower size edge
            dwCurrentSize = 0;
            while((dwCurrentSize<MAX_BF_BUFFER_SIZE)
                && (!DeviceIoControl(hDevice,pIOCTLStorage[i].dwIOCTL, pDummyBuffer, dwCurrentSize, pDummyBuffer, MAX_BF_BUFFER_SIZE, &dwBytesReturned, NULL))
                && (GetLastError()==ERROR_INVALID_PARAMETER)) {
                    dwCurrentSize++;
            }
            //If an IOCTL either
            //1. Requires a buffer larger than supported
            //or
            //2. Performs a strict check on the outgoing buffer
            //we will hit this if statement.
            if(dwCurrentSize>=MAX_BF_BUFFER_SIZE) {
                TPRINT(LEVEL_INFO_ALL, L" Failed to find lower edge. Skipping.\n");
                pIOCTLStorage[i].dwLowerSize = INVALID_BUFFER_SIZE;
                pIOCTLStorage[i].dwUpperSize = INVALID_BUFFER_SIZE;
            }
            else {
                TPRINT(LEVEL_INFO_ALL, L" Found lower size edge at %d bytes\n", dwCurrentSize);
                pIOCTLStorage[i].dwLowerSize = dwCurrentSize;
                //find upper size edge
                dwCurrentSize = MAX_BF_BUFFER_SIZE;
                while((dwCurrentSize >= pIOCTLStorage[i].dwLowerSize)
                    && (!DeviceIoControl(hDevice, pIOCTLStorage[i].dwIOCTL, pDummyBuffer, dwCurrentSize, pDummyBuffer, MAX_BF_BUFFER_SIZE, &dwBytesReturned, NULL))
                    && (GetLastError()==ERROR_INVALID_PARAMETER)) {
                        dwCurrentSize--;
                }
                TPRINT(LEVEL_INFO_ALL, L" Found upper size edge at %d bytes\n", dwCurrentSize);
                pIOCTLStorage[i].dwUpperSize = dwCurrentSize;
            }
            //go to next IOCTL
            i++;
        } // while
        HeapFree(GetProcessHeap(), 0, pDummyBuffer);
    } // if pDummyBuffer
    else {
        bResult = FALSE;
        TPRINT(LEVEL_ERROR, L"Failed to allocate dummy buffer\n");
    }
    return bResult;
}

//DESCRIPTION:
// Writes all bruteforce resuls to a log file (dibf-bf-results.txt).
//
//INPUT:
// pDeviceName - Pointer to device object name.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
//
//OUTPUT:
// None.
//
BOOL WriteBruteforceResult(TCHAR *pDeviceName, PIOCTL_STORAGE pIOCTLStorage)
{
    BOOL bResult=FALSE;
    HANDLE hFile;
    TCHAR cScratchBuffer[MAX_PATH];
    DWORD dwBytesWritten, i=0;

    hFile = CreateFile(DIBF_BF_LOG_FILE, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile!=INVALID_HANDLE_VALUE) {
        //write device name
        if(-1!=_sntprintf_s(cScratchBuffer, MAX_PATH, _TRUNCATE, L"%s\n", pDeviceName)) {
            if(WriteFile(hFile, cScratchBuffer, _tcslen(cScratchBuffer)*sizeof(TCHAR), &dwBytesWritten, NULL)) {
                //write all IOCTLs and their sizes
                while((i<MAX_IOCTLS) && (pIOCTLStorage[i].dwIOCTL!=0)) {
                    _sntprintf_s(cScratchBuffer, MAX_PATH, _TRUNCATE, L"%x %d %d\n", pIOCTLStorage[i].dwIOCTL, pIOCTLStorage[i].dwLowerSize, pIOCTLStorage[i].dwUpperSize);
                    WriteFile(hFile, cScratchBuffer, _tcslen(cScratchBuffer)*sizeof(TCHAR), &dwBytesWritten, NULL);
                    i++;
                }
            } // if WriteFile
            else {
                TPRINT(LEVEL_ERROR, L"Error writing to log file %s, %d\n", DIBF_BF_LOG_FILE, GetLastError());
            }
        }
        else {
            TPRINT(LEVEL_ERROR, L"snprintf error\n"); // add errno output
        }
        CloseHandle(hFile);
    } // if hFile != INVALID_HANDLE_VALUE
    else {
        TPRINT(LEVEL_ERROR, L"Error creating/opening log file %s, %d\n", DIBF_BF_LOG_FILE, GetLastError());
    }
    return bResult;
}

//DESCRIPTION:
// Reads all bruteforce resuls from a log file (dibf-bf-results.txt).
//
//INPUT:
// pDeviceName - Pointer to device object name.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
// dwIOCTLCount - output pointer to number of ioctls found
//
//OUTPUT:
// Populates pDeviceName, pIOCTLStorage and dwIOCTLCount. Returns a bool indicating
// if the read was successful or not.
//
BOOL ReadBruteforceResult(TCHAR *pDeviceName, PIOCTL_STORAGE pIOCTLStorage, PDWORD dwIOCTLCount)
{
    HANDLE hFile=INVALID_HANDLE_VALUE;
    DWORD error, dwFileSize, dwBytesRead, dwIOCTLIndex = 0;
    TCHAR *pBuffer=NULL, *pCurrent;
    BOOL result=FALSE, resint;
    INT charsRead=0, res;

    hFile = CreateFile(DIBF_BF_LOG_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile!=INVALID_HANDLE_VALUE) {
        dwFileSize = GetFileSize(hFile, NULL);
        if(dwFileSize!=INVALID_FILE_SIZE) {
            if((dwFileSize >= 6) && (dwFileSize <= MAX_IOCTLS * sizeof(IOCTL_STORAGE) + MAX_PATH*sizeof(TCHAR))) {
                pBuffer = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, dwFileSize+sizeof(TCHAR));
                if(pBuffer) {
                    resint = ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL);
                    if(resint && (dwFileSize==dwBytesRead)) {
                        // Make sure our buffer is null terminated
                        pBuffer[dwFileSize/sizeof(TCHAR)] = L'\0';
                        // First, read the device name
                        pCurrent = pBuffer;
                        res = _stscanf_s(pCurrent, L"%[^\n]%n", pDeviceName, MAX_PATH, &charsRead);
                        pCurrent += charsRead+1; // Read past the string and the terminating \n
                        if(res==1) {
                            //now, read up all the IOCTLs and their size edges
                            do {
                                res =_stscanf_s(pCurrent, L"%x %d %d%n[^\n]", &pIOCTLStorage[dwIOCTLIndex].dwIOCTL, &pIOCTLStorage[dwIOCTLIndex].dwLowerSize, &pIOCTLStorage[dwIOCTLIndex].dwUpperSize, &charsRead);
                                pCurrent += charsRead+1;
                            }
                            while(res==3 && ++dwIOCTLIndex<MAX_IOCTLS);
                            TPRINT(LEVEL_INFO, L"Found and successfully loaded values from %s\n", DIBF_BF_LOG_FILE);
                            TPRINT(LEVEL_INFO, L" Device name: %s\n", pDeviceName);
                            TPRINT(LEVEL_INFO, L" Number of IOCTLs: %d\n", dwIOCTLIndex);
                            // Write back the number of IOCTLs
                            *dwIOCTLCount = dwIOCTLIndex;
                            result = TRUE;
                        }
                        else{
                            TPRINT(LEVEL_ERROR, L"Reading device name from log file %s failed.\n", DIBF_BF_LOG_FILE);
                        }
                    } // if resint and read ok
                    else {
                        if(!resint) {
                            TPRINT(LEVEL_ERROR, L"Reading log file %s failure %x\n", DIBF_BF_LOG_FILE, GetLastError());
                        }
                        else {
                            TPRINT(LEVEL_ERROR, L"Reading log file %s succeeded but wrong size read: expected 0x%x, got 0x%x\n", DIBF_BF_LOG_FILE, dwFileSize, dwBytesRead);
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, pBuffer);
                } // if pBuffer
            } // if size ok
            else {
                TPRINT(LEVEL_ERROR, L"Log file %s size (%u) is invalid\n", DIBF_BF_LOG_FILE, dwFileSize);
            }
        } // if GetFileSize
        else {
            TPRINT(LEVEL_ERROR, L"GetFileSize on %s failed with error %x\n", DIBF_BF_LOG_FILE, GetLastError());
        }
        CloseHandle(hFile);
    } // if hfile != INVALID_HANDLE_VALUE
    else {
        error=GetLastError();
        if(error==ERROR_FILE_NOT_FOUND) {
            TPRINT(LEVEL_ERROR, L"No existing %s file found\n", DIBF_BF_LOG_FILE);
        }
        else {
            TPRINT(LEVEL_ERROR, L"Failed to open Log file %s with error %x\n", DIBF_BF_LOG_FILE, GetLastError());
        }
    }
    return result;
}

//DESCRIPTION:
// Packs all the parameters in a config structure before passing it
// to the individual fuzzer stages.
//
//INPUT:
// hDevice - Handle to device object.
// pIOCTLStorage - Pointer to array of IOCTL_STORAGE structures.
// dwFuzzStage - DWORD indicating which stages to run.
// dwIOCTLCount - the number of IOCTLs in pIOCTLStorage
// maxThreads - the number of threads to create for the async fuzzer
// timeLimits - the 3 timeout values (1 for each fuzzer)
// maxPending - the max number of pending requests for the async fuzzer
// cancelRate - the percentage of requests to attempt cancelling for the async fuzzer
//
//OUTPUT:
// None.
//
VOID FuzzIOCTLs(HANDLE hDevice, PIOCTL_STORAGE pIOCTLStorage, DWORD dwFuzzStage, DWORD dwIOCTLCount, ULONG maxThreads, PULONG timeLimits, ULONG maxPending, ULONG cancelRate)
{
    TRACKER tracker = {0};

    InitializeFuzzersTermination();
    // If enabled by command line, run pure random fuzzer
    if(timeLimits[0]&&(dwFuzzStage & RANDOM_FUZZER)==RANDOM_FUZZER) {
        TPRINT(LEVEL_ALWAYS_PRINT, L"<<<< RUNNING RANDOM FUZZER >>>>\n");
        printDateTime(FALSE);
        StartSyncFuzzer(RandomFuzzer, hDevice, pIOCTLStorage, dwIOCTLCount, timeLimits[0], &tracker);
        printTracker(&tracker);
    }
    // If enabled by command line, run sliding DWORD fuzzer
    if(timeLimits[1]&&(dwFuzzStage & DWORD_FUZZER) == DWORD_FUZZER) {
        TPRINT(LEVEL_ALWAYS_PRINT, L"<<<< RUNNING SLIDING DWORD FUZZER >>>>\n");
        printDateTime(FALSE);
        StartSyncFuzzer(SlidingDWORDFuzzer, hDevice, pIOCTLStorage, dwIOCTLCount, timeLimits[1], &tracker);
        printTracker(&tracker);
    }
    // If enabled by command line, run async fuzzer
    if(timeLimits[2]&&(dwFuzzStage & ASYNC_FUZZER) == ASYNC_FUZZER) {
        TPRINT(LEVEL_ALWAYS_PRINT, L"<<<< RUNNING ASYNC FUZZER >>>>\n");
        printDateTime(FALSE);
        Asyncfuzzer(hDevice, pIOCTLStorage, dwIOCTLCount, maxThreads, timeLimits[2], maxPending, cancelRate, &tracker);
        printTracker(&tracker);
    } // if async fuzzer
    // Unregister
    if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, FALSE)) {
        TPRINT(LEVEL_WARNING, L"\n WARNING: FAILED TO UNREGISTER CONTROL HANDLER\n");
    }
    return;
}

//DESCRIPTION:
// Displays usage information.
//
//INPUT:
// None.
//
//OUTPUT:
// None.
//
VOID usage(void)
{
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------------------------------------------\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"DIBF - Device IOCTL Bruteforcer and Fuzzer\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"(C)2014 andreas at isecpartners dot com\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"(C)2014 nguigo at isecpartners dot com\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"---------------------------------------------------------------------------\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Usage:\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" dibf <options> <device name>\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Options:\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -h You're looking at it\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -i Ignore (OVERWRITE) previous logfile\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -d Deep IOCTL bruteforce (8-9 times slower)\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -v [0-3] Verbosity level\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -s [ioctl] Start IOCTL value\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -e [ioctl] End IOCTL value\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -t [d1,d2,d4] Timeout for each fuzzer in seconds -- no spaces and decimal input ONLY\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" -p [max requests] Max number of async pending requests (loosely enforced, default %d)\n", MAX_PENDING);
    TPRINT(LEVEL_ALWAYS_PRINT, L" -a [max threads] Max number of threads, default is 2xNbOfProcessors, max is %d\n", MAX_THREADS);
    TPRINT(LEVEL_ALWAYS_PRINT, L" -c [%% cancelation] Async cancelation attempt percent rate (default %d)\n", CANCEL_RATE);
    TPRINT(LEVEL_ALWAYS_PRINT, L" -f [0-7] Fuzz flag. OR values together to run multiple\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          fuzzer stages. If left out, it defaults to all\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          stages.\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          0 = Brute-force IOCTLs only\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          1 = Random\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          2 = Sliding DWORD\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"          4 = Async / Pending\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Examples:\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" dibf \\\\.\\MyDevice\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" dibf -v -d -s 0x10000000 \\\\.\\MyDevice\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" dibf -f 0x3 \\\\.\\MyDevice\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"Notes:\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" - The bruteforce stage will generate a file named \"dibf-bf-results.txt\"\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"   in the same directory as the executable. If dibf is started with no\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"   arguments, it will look for this file and start the fuzzer with the values\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L"   from it.\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" - If not specified otherwise, command line arguments can be passed as decimal or hex (prefix with \"0x\")\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" - CTRL-C interrupts the current stage and moves to the next if any. Current statistics will be displayed.\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" - The statistics are cumulative.\n");
    TPRINT(LEVEL_ALWAYS_PRINT, L" - The command-line flags are case-insensitive.\n");
}
