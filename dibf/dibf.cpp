/***********************************************************************************
* dib.cpp : Defines the entry point for the console application.                   *
*                                                                                  *
* TODO:                                                                            *
* - Alter code to be resilient against IOCTLs that lock                            *
* - Add functionality to guess valid output size                                   *
* - Check that error codes for guessing are adequate                               *
* - Implement ctrl-c handling in ioctl guessing stage                              *
************************************************************************************/

#include "stdafx.h"
#include "dibf.h"
#include "AsyncFuzzer.h"
#include "SyncFuzzer.h"

Dibf::Dibf()
{
    TPRINT(VERBOSITY_DEBUG, L"Dibf constructor\n");
    return;
}

Dibf::~Dibf()
{
    TPRINT(VERBOSITY_DEBUG, L"Dibf destructor\n");
    return;
}

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
BOOL Dibf::readAndValidateCommandLineUlong(LPTSTR str, ULONG lowerBound, ULONG upperBound, PULONG out, BOOL check)
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

BOOL Dibf::DoAllBruteForce(PTSTR pDeviceName, DWORD dwIOCTLStart, DWORD dwIOCTLEnd, BOOL deep)
{
    BOOL bResult=FALSE;

    HANDLE hDevice = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(hDevice!=INVALID_HANDLE_VALUE) {
        //Bruteforce IOCTLs
        TPRINT(VERBOSITY_DEFAULT, L"<<<< GUESSING IOCTLS %s>>>>\n", deep?L"(DEEP MODE)":L"");
        TPRINT(VERBOSITY_INFO, L"Bruteforcing ioctl codes\n");
        bResult = BruteForceIOCTLs(hDevice, dwIOCTLStart, dwIOCTLEnd, deep);
        if(bResult) {
            TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------\n\n");
            TPRINT(VERBOSITY_INFO, L"Bruteforcing buffer sizes\n");
            bResult = BruteForceBufferSizes(hDevice);
            if(bResult) {
                TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------\n\n");
                WriteBruteforceResult(pDeviceName, &IOCTLStorage);
            }
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"Unable to find any valid IOCTLs, exiting...\n");
            hDevice = INVALID_HANDLE_VALUE;
        }
        CloseHandle(hDevice);
    }
    else {
        TPRINT(VERBOSITY_ERROR, L"Unable to open device %s, error %#.8x\n", pDeviceName, GetLastError());
    }
    return bResult;
}

BOOL Dibf::start(INT argc, _TCHAR* argv[])
{
    HANDLE hDevice=INVALID_HANDLE_VALUE;
    BOOL bDeepBruteForce=FALSE, bIoctls=FALSE, validUsage=TRUE, bIgnoreFile=FALSE, gotDeviceName=FALSE;
    DWORD dwIOCTLStart=START_IOCTL_VALUE, dwIOCTLEnd=END_IOCTL_VALUE, dwFuzzStage=0xf;
    ULONG maxThreads=0, timeLimits[3]={INFINITE, INFINITE,INFINITE}, cancelRate=CANCEL_RATE, maxPending=MAX_PENDING;
    LONG i=1;

    // Process options
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
                    TPRINT(VERBOSITY_DEFAULT, L"Invalid verbosity level or bad syntax.\n");
                    validUsage = FALSE;
                }
                break;
            case L's':
            case L'S':
                if((i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLStart, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'e':
            case L'E':
                if((i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLEnd, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
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
                        TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
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
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'p':
            case L'P':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &maxPending, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'c':
            case L'C':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 100, &cancelRate, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'f':
            case L'F':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 7, &dwFuzzStage, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, L"Parsing error for flag -%c.\n", argv[i][1]);
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
                bIgnoreFile = TRUE;
                break;
            default:
                validUsage = FALSE;
                break;
            }
        } // if
        else {
            // If this is the last parameter, it has to be the device name
            if(i==argc-1) {
                gotDeviceName = 0==_tcsncpy_s(pDeviceName, MAX_PATH, argv[i], _TRUNCATE);
            }
            else {
                validUsage = FALSE;
            }
        }
    } // for
    if(validUsage) {
        // Unless -i
        if(!bIgnoreFile) {
            // Attempt to read file
            TPRINT(VERBOSITY_DEFAULT, L"<<<< CAPTURING IOCTL DEFINITIONS FROM FILE >>>>\n");
            bIoctls = ReadBruteforceResult(pDeviceName, &gotDeviceName, &IOCTLStorage);
        }
        // If we don't have thee ioctls defs from file
        if(!bIoctls) {
            if(gotDeviceName) {
                // Open the device based on the file name passed from params, fuzz the IOCTLs and return the device handle
                bIoctls = DoAllBruteForce(pDeviceName, dwIOCTLStart, dwIOCTLEnd, bDeepBruteForce);
                if(!bIoctls) {
                    TPRINT(VERBOSITY_ERROR, L"Failed to guess IOCTLs, exiting\n");
                }
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"No valid device name provided, exiting\n");
            }
        }
        // At this point we need ioctl defs
        if(bIoctls) {
            // We got them from file, check that device is ok
            if(INVALID_HANDLE_VALUE!=(hDevice = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL))) {
                CloseHandle(hDevice);
                // Got a valid handle and valid IOCTLS to fuzz, onto actual fuzzing
                FuzzIOCTLs(dwFuzzStage, maxThreads, timeLimits, maxPending, cancelRate);
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Error opening device %s, error %d\n", pDeviceName, GetLastError());
            }
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
// FALSE if no ioctl was found, TRUE otherwise
BOOL Dibf::BruteForceIOCTLs(HANDLE hDevice, DWORD dwIOCTLStart, DWORD dwIOCTLEnd, BOOL bDeepBruteForce)
{
    DWORD dwIOCTL, dwIOCTLIndex=0;
    IoRequest ioRequest(hDevice);  // This unique request gets reused iteratively

    for(dwIOCTL=dwIOCTLStart; dwIOCTL<=dwIOCTLEnd; dwIOCTL++) {
        ioRequest.SetIoCode(dwIOCTL);
        if(ioRequest.testSendForValidRequest(bDeepBruteForce)) {
            if(dwIOCTLIndex<MAX_IOCTLS) {
                IOCTLStorage.ioctls[dwIOCTLIndex++].dwIOCTL = dwIOCTL;
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Found IOCTL but out of storage space, stopping bruteforce\n");
                return MAX_IOCTLS;
            }
        }
        if(dwIOCTL % 0x010000 == 0) {
            TPRINT(VERBOSITY_INFO, L"Current iocode: %#.8x (found %u ioctls so far)\n", dwIOCTL, dwIOCTLIndex);
        }
    }
    IOCTLStorage.count=dwIOCTLIndex;
    TPRINT(VERBOSITY_ALL, L"Found %u ioctls\n", dwIOCTLIndex);
    return dwIOCTLIndex!=0;
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
BOOL Dibf::BruteForceBufferSizes(HANDLE hDevice)
{
    BOOL bResult=TRUE;
    DWORD dwCurrentSize;
    IoRequest ioRequest(hDevice);  // This unique request gets reused iteratively

    for(ULONG i=0; i<IOCTLStorage.count; i++) {
        TPRINT(VERBOSITY_INFO, L" Working on IOCTL %#.8x\n", IOCTLStorage.ioctls[i].dwIOCTL);
        // Find lower size edge
        ioRequest.SetIoCode(IOCTLStorage.ioctls[i].dwIOCTL);
        dwCurrentSize = 0;
        while((dwCurrentSize<MAX_BUFSIZE) && !ioRequest.testSendForValidBufferSize(dwCurrentSize)) {
            dwCurrentSize++;
        }
        // If an IOCTL either requires a buffer larger than supported or performs a strict check on the outgoing buffer
        if(dwCurrentSize==MAX_BUFSIZE) {
            TPRINT(VERBOSITY_ALL, L" Failed to find lower edge. Skipping.\n");
            IOCTLStorage.ioctls[i].dwLowerSize = 0;
            IOCTLStorage.ioctls[i].dwUpperSize = MAX_BUFSIZE;
        }
        else {
            TPRINT(VERBOSITY_ALL, L" Found lower size edge at %d bytes\n", dwCurrentSize);
            IOCTLStorage.ioctls[i].dwLowerSize = dwCurrentSize;
            // Find upper size edge
            while((dwCurrentSize<MAX_BUFSIZE) && ioRequest.testSendForValidBufferSize(dwCurrentSize)) {
                dwCurrentSize++;
            }
            TPRINT(VERBOSITY_ALL, L" Found upper size edge at %d bytes\n", dwCurrentSize);
            IOCTLStorage.ioctls[i].dwUpperSize = dwCurrentSize;
        }
    } // while
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
BOOL Dibf::WriteBruteforceResult(TCHAR *pDeviceName, IoctlStorage *pIOCTLStorage)
{
    BOOL bResult=FALSE;
    HANDLE hFile;
    TCHAR cScratchBuffer[MAX_PATH];
    DWORD dwBytesWritten, i=0;

    hFile = CreateFile(DIBF_BF_LOG_FILE, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile!=INVALID_HANDLE_VALUE) {
        //write device name
        if(-1!=_sntprintf_s(cScratchBuffer, MAX_PATH, _TRUNCATE, L"%s\n", pDeviceName)) {
            bResult = WriteFile(hFile, cScratchBuffer, _tcslen(cScratchBuffer)*sizeof(TCHAR), &dwBytesWritten, NULL);
            //write all IOCTLs and their sizes
            while(bResult && (i<MAX_IOCTLS) && (pIOCTLStorage->ioctls[i].dwIOCTL!=0)) {
                _sntprintf_s(cScratchBuffer, MAX_PATH, _TRUNCATE, L"%x %d %d\n", pIOCTLStorage->ioctls[i].dwIOCTL, pIOCTLStorage->ioctls[i].dwLowerSize, pIOCTLStorage->ioctls[i].dwUpperSize);
                bResult = WriteFile(hFile, cScratchBuffer, _tcslen(cScratchBuffer)*sizeof(TCHAR), &dwBytesWritten, NULL);
                i++;
            }
            if(bResult) {
                TPRINT(VERBOSITY_INFO, L"Successfully written IOCTLs data to log file %s\n", DIBF_BF_LOG_FILE);
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Error writing to log file %s, %d\n", DIBF_BF_LOG_FILE, GetLastError());
            }
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"snprintf error\n"); // add errno output
        }
        CloseHandle(hFile);
    } // if hFile != INVALID_HANDLE_VALUE
    else {
        TPRINT(VERBOSITY_ERROR, L"Error creating/opening log file %s, %d\n", DIBF_BF_LOG_FILE, GetLastError());
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
BOOL Dibf::ReadBruteforceResult(TCHAR *clDeviceName, BOOL *pGotDeviceName, IoctlStorage *pIOCTLStorage)
{
    HANDLE hFile=INVALID_HANDLE_VALUE;
    DWORD error, dwFileSize, dwBytesRead, dwIOCTLIndex = 0;
    TCHAR *pBuffer=NULL, *pCurrent;
    BOOL bResult=FALSE, resint;
    INT charsRead=0, res;
    TCHAR deviceName[MAX_PATH];
    BOOL gotDeviceName=*pGotDeviceName;

    hFile = CreateFile(DIBF_BF_LOG_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile!=INVALID_HANDLE_VALUE) {
        dwFileSize = GetFileSize(hFile, NULL);
        if(dwFileSize!=INVALID_FILE_SIZE) {
            if((dwFileSize >= 6) && (dwFileSize <= MAX_IOCTLS * sizeof(IoctlStorage) + MAX_PATH*sizeof(TCHAR))) {
                pBuffer = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, dwFileSize+sizeof(TCHAR));
                if(pBuffer) {
                    resint = ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL);
                    if(resint && (dwFileSize==dwBytesRead)) {
                        // Make sure our buffer is null terminated
                        pBuffer[dwFileSize/sizeof(TCHAR)] = L'\0';
                        // First, read the device name
                        pCurrent = pBuffer;
                        res = _stscanf_s(pCurrent, L"%[^\n]%n", gotDeviceName?deviceName:clDeviceName, MAX_PATH, &charsRead);
                        pCurrent += charsRead+1; // Read past the string and the terminating \n
                        if(res==1) {
                            if(gotDeviceName && _tcscmp(deviceName, clDeviceName)) {
                                TPRINT(VERBOSITY_ERROR, L"Device name from command line (%s) and from existing %s file (%s) differ, aborting\n", clDeviceName, DIBF_BF_LOG_FILE, deviceName);
                                *pGotDeviceName=FALSE;
                            }
                            else {
                                //now, read up all the IOCTLs and their size edges
                                do {
                                    res =_stscanf_s(pCurrent, L"%x %d %d%n[^\n]", &pIOCTLStorage->ioctls[dwIOCTLIndex].dwIOCTL, &pIOCTLStorage->ioctls[dwIOCTLIndex].dwLowerSize, &pIOCTLStorage->ioctls[dwIOCTLIndex].dwUpperSize, &charsRead);
                                    pCurrent += charsRead+1;
                                    if(res==3) {
                                        TPRINT(VERBOSITY_ALL, L"Loaded IOCTL %#.8x [%u, %u]\n", pIOCTLStorage->ioctls[dwIOCTLIndex].dwIOCTL, pIOCTLStorage->ioctls[dwIOCTLIndex].dwLowerSize, pIOCTLStorage->ioctls[dwIOCTLIndex].dwUpperSize);
                                    }
                                }
                                while(res==3 && ++dwIOCTLIndex<MAX_IOCTLS);
                                TPRINT(VERBOSITY_DEFAULT, L"Found and successfully loaded values from %s\n", DIBF_BF_LOG_FILE);
                                TPRINT(VERBOSITY_INFO, L" Device name: %s\n", gotDeviceName?deviceName:clDeviceName);
                                TPRINT(VERBOSITY_INFO, L" Number of IOCTLs: %d\n", dwIOCTLIndex);
                                // Write back the number of IOCTLs
                                pIOCTLStorage->count = dwIOCTLIndex;
                                bResult = TRUE;
                            }
                        }
                        else{
                            TPRINT(VERBOSITY_ERROR, L"Reading device name from log file %s failed.\n", DIBF_BF_LOG_FILE);
                        }
                    } // if resint and read ok
                    else {
                        if(!resint) {
                            TPRINT(VERBOSITY_ERROR, L"Reading log file %s failure %x\n", DIBF_BF_LOG_FILE, GetLastError());
                        }
                        else {
                            TPRINT(VERBOSITY_ERROR, L"Reading log file %s succeeded but wrong size read: expected 0x%x, got 0x%x\n", DIBF_BF_LOG_FILE, dwFileSize, dwBytesRead);
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, pBuffer);
                } // if pBuffer
            } // if size ok
            else {
                TPRINT(VERBOSITY_ERROR, L"Log file %s size (%u) is invalid\n", DIBF_BF_LOG_FILE, dwFileSize);
            }
        } // if GetFileSize
        else {
            TPRINT(VERBOSITY_ERROR, L"GetFileSize on %s failed with error %x\n", DIBF_BF_LOG_FILE, GetLastError());
        }
        CloseHandle(hFile);
    } // if hfile != INVALID_HANDLE_VALUE
    else {
        error=GetLastError();
        if(error==ERROR_FILE_NOT_FOUND) {
            TPRINT(VERBOSITY_ERROR, L"No existing %s file found\n", DIBF_BF_LOG_FILE);
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"Failed to open Log file %s with error %x\n", DIBF_BF_LOG_FILE, GetLastError());
        }
    }
    return bResult;
}

//DESCRIPTION:
// Packs all the parameters in a config structure before passing it
// to the individual fuzzer stages.
//
//INPUT:
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
VOID Dibf::FuzzIOCTLs(DWORD dwFuzzStage, ULONG maxThreads, PULONG timeLimits, ULONG maxPending, ULONG cancelRate)
{
    HANDLE hDev=INVALID_HANDLE_VALUE;

    hDev = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    // If enabled by command line, run sliding DWORD fuzzer
    if(hDev!=INVALID_HANDLE_VALUE&&timeLimits[0]&&(dwFuzzStage & DWORD_FUZZER) == DWORD_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, L"<<<< RUNNING SLIDING DWORD FUZZER >>>>\n");
        Fuzzer::printDateTime(FALSE);
        SyncFuzzer *syncf = new SyncFuzzer(hDev, timeLimits[0], new SlidingDwordFuzzer(&IOCTLStorage));
        if(syncf->init()) {
            syncf->start();
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"SlidingDWORD fuzzer init failed. Aborting run.\n");
        }
        Fuzzer::tracker.stats.print();
        delete syncf;
        CloseHandle(hDev);
    }

    hDev = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    // If enabled by command line, run pure random fuzzer
    if(hDev!=INVALID_HANDLE_VALUE&&timeLimits[1]&&(dwFuzzStage & RANDOM_FUZZER)==RANDOM_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, L"<<<< RUNNING RANDOM FUZZER >>>>\n");
        Fuzzer::printDateTime(FALSE);
        AsyncFuzzer *asyncf = new AsyncFuzzer(hDev, timeLimits[1], maxPending, cancelRate, new Dumbfuzzer(&IOCTLStorage));
        if(asyncf->init(maxThreads)) {
            asyncf->start();
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"Dumbfuzzer init failed. Aborting run.\n");
        }
        Fuzzer::tracker.stats.print();
        delete asyncf;
        CloseHandle(hDev);
    }

    hDev = CreateFile(pDeviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    // If enabled by command line, run custom fuzzer (taking input from named pipe)
    if(hDev!=INVALID_HANDLE_VALUE&&timeLimits[2]&&(dwFuzzStage & NP_FUZZER) == NP_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, L"<<<< RUNNING CUSTOM FUZZER >>>>\n");
        Fuzzer::printDateTime(FALSE);
        AsyncFuzzer *customFuzzer=NULL;
        NamedPipeInputFuzzer *pipef = new NamedPipeInputFuzzer();
        if(pipef->Init()) {
            customFuzzer = new AsyncFuzzer(hDev, timeLimits[2], maxPending, cancelRate, pipef);
            if(customFuzzer->init(maxThreads)) {
                customFuzzer->start();
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Custom fuzzer init failed. Aborting run.\n");
            }
            delete customFuzzer;
        }
        else {
            TPRINT(VERBOSITY_ERROR, L"Failed to initialize named pipe fuzzing provider. Aborting run.\n");
        }
        Fuzzer::tracker.stats.print();
        CloseHandle(hDev);
    } // if async fuzzer
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
VOID Dibf::usage(VOID)
{
    TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------------------------------------------\n");
    TPRINT(VERBOSITY_DEFAULT, L"DIBF - Device IOCTL Bruteforcer and Fuzzer\n");
    TPRINT(VERBOSITY_DEFAULT, L"(C)2014-2015 andreas at isecpartners dot com\n");
    TPRINT(VERBOSITY_DEFAULT, L"(C)2014-2015 nguigo at isecpartners dot com\n");
    TPRINT(VERBOSITY_DEFAULT, L"---------------------------------------------------------------------------\n");
    TPRINT(VERBOSITY_DEFAULT, L"Usage:\n");
    TPRINT(VERBOSITY_DEFAULT, L" dibf <options> <device name>\n");
    TPRINT(VERBOSITY_DEFAULT, L"Options:\n");
    TPRINT(VERBOSITY_DEFAULT, L" -h You're looking at it\n");
    TPRINT(VERBOSITY_DEFAULT, L" -i Ignore (OVERWRITE) previous logfile\n");
    TPRINT(VERBOSITY_DEFAULT, L" -d Deep IOCTL bruteforce (8-9 times slower)\n");
    TPRINT(VERBOSITY_DEFAULT, L" -v [0-3] Verbosity level\n");
    TPRINT(VERBOSITY_DEFAULT, L" -s [ioctl] Start IOCTL value\n");
    TPRINT(VERBOSITY_DEFAULT, L" -e [ioctl] End IOCTL value\n");
    TPRINT(VERBOSITY_DEFAULT, L" -t [d1,d2,d4] Timeout for each fuzzer in seconds -- no spaces and decimal input ONLY\n");
    TPRINT(VERBOSITY_DEFAULT, L" -p [max requests] Max number of async pending requests (loosely enforced, VERBOSITY_DEFAULT %d)\n", MAX_PENDING);
    TPRINT(VERBOSITY_DEFAULT, L" -a [max threads] Max number of threads, VERBOSITY_DEFAULT is 2xNbOfProcessors, max is %d\n", MAX_THREADS);
    TPRINT(VERBOSITY_DEFAULT, L" -c [%% cancelation] Async cancelation attempt percent rate (VERBOSITY_DEFAULT %d)\n", CANCEL_RATE);
    TPRINT(VERBOSITY_DEFAULT, L" -f [0-7] Fuzz flag. OR values together to run multiple\n");
    TPRINT(VERBOSITY_DEFAULT, L"          fuzzer stages. If left out, it defaults to all\n");
    TPRINT(VERBOSITY_DEFAULT, L"          stages.\n");
    TPRINT(VERBOSITY_DEFAULT, L"          0 = Brute-force IOCTLs only\n");
    TPRINT(VERBOSITY_DEFAULT, L"          1 = Sliding DWORD (sync)\n");
    TPRINT(VERBOSITY_DEFAULT, L"          2 = Random (async)\n");
    TPRINT(VERBOSITY_DEFAULT, L"          4 = Named Pipe (async)\n");
    TPRINT(VERBOSITY_DEFAULT, L"Examples:\n");
    TPRINT(VERBOSITY_DEFAULT, L" dibf \\\\.\\MyDevice\n");
    TPRINT(VERBOSITY_DEFAULT, L" dibf -v -d -s 0x10000000 \\\\.\\MyDevice\n");
    TPRINT(VERBOSITY_DEFAULT, L" dibf -f 0x3 \\\\.\\MyDevice\n");
    TPRINT(VERBOSITY_DEFAULT, L"Notes:\n");
    TPRINT(VERBOSITY_DEFAULT, L" - The bruteforce stage will generate a file named \"dibf-bf-results.txt\"\n");
    TPRINT(VERBOSITY_DEFAULT, L"   in the same directory as the executable. If dibf is started with no\n");
    TPRINT(VERBOSITY_DEFAULT, L"   arguments, it will look for this file and start the fuzzer with the values\n");
    TPRINT(VERBOSITY_DEFAULT, L"   from it.\n");
    TPRINT(VERBOSITY_DEFAULT, L" - If not specified otherwise, command line arguments can be passed as decimal or hex (prefix with \"0x\")\n");
    TPRINT(VERBOSITY_DEFAULT, L" - CTRL-C interrupts the current stage and moves to the next if any. Current statistics will be displayed.\n");
    TPRINT(VERBOSITY_DEFAULT, L" - The statistics are cumulative.\n");
    TPRINT(VERBOSITY_DEFAULT, L" - The command-line flags are case-insensitive.\n");
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
INT _tmain(INT argc, _TCHAR* argv[])
{
    Dibf dibf;
    dibf.start(argc, argv);
    return 0;
}
