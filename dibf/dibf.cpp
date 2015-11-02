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

static BOOL userCtrlBreak;

Dibf::Dibf() : gotDeviceName(FALSE)
{
    TPRINT(VERBOSITY_DEBUG, _T("Dibf constructor\n"));
    return;
}

Dibf::~Dibf()
{
    TPRINT(VERBOSITY_DEBUG, _T("Dibf destructor\n"));
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

BOOL Dibf::DoAllBruteForce(DWORD dwIOCTLStart, DWORD dwIOCTLEnd, BOOL deep)
{
    BOOL bResult=FALSE;

    HANDLE hDevice = CreateFile(deviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(hDevice!=INVALID_HANDLE_VALUE) {
        //Bruteforce IOCTLs
        TPRINT(VERBOSITY_DEFAULT, _T("<<<< GUESSING IOCTLS %s>>>>\n"), deep?_T("(DEEP MODE)"):_T(""));
        TPRINT(VERBOSITY_INFO, _T("Bruteforcing ioctl codes\n"));
        SmartBruteCheck(hDevice, dwIOCTLStart, dwIOCTLEnd, deep);
        bResult = BruteForceIOCTLs(hDevice, dwIOCTLStart, dwIOCTLEnd, deep);
        if(bResult) {
            TPRINT(VERBOSITY_DEFAULT, _T("---------------------------------------\n\n"));
            TPRINT(VERBOSITY_INFO, _T("Bruteforcing buffer sizes\n"));
            bResult = BruteForceBufferSizes(hDevice);
            if(bResult) {
                TPRINT(VERBOSITY_DEFAULT, _T("---------------------------------------\n\n"));
                WriteBruteforceResult();
            }
        }
        else {
            TPRINT(VERBOSITY_ERROR, _T("Unable to find any valid IOCTLs, exiting...\n"));
            hDevice = INVALID_HANDLE_VALUE;
        }
        CloseHandle(hDevice);
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Unable to open device %s, error %#.8x\n"), (LPCTSTR)deviceName, GetLastError());
    }
    return bResult;
}

BOOL Dibf::start(INT argc, _TCHAR* argv[])
{
    BOOL bDeepBruteForce=FALSE, bIoctls=FALSE, validUsage=TRUE, bIgnoreFile=FALSE;
    DWORD dwIOCTLStart=START_IOCTL_VALUE, dwIOCTLEnd=END_IOCTL_VALUE, dwFuzzStage=0x3;
    ULONG maxThreads=0, timeLimits[3]={INFINITE, INFINITE,INFINITE}, cancelRate=CANCEL_RATE, maxPending=MAX_PENDING;
    gotFileName = FALSE;
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
                    TPRINT(VERBOSITY_DEFAULT, _T("Invalid verbosity level or bad syntax.\n"));
                    validUsage = FALSE;
                }
                break;
            case L's':
            case L'S':
                if((i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLStart, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'e':
            case L'E':
                if((i<argc-1) && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &dwIOCTLEnd, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L't':
            case L'T':
                if(i<argc-1 && 3==_stscanf_s(argv[i+1], _T("%u,%u,%u"), &timeLimits[0], &timeLimits[1], &timeLimits[2]))
                    {
                        i++;
                    }
                    else {
                        TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
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
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'p':
            case L'P':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 0, &maxPending, FALSE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'c':
            case L'C':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 100, &cancelRate, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            case L'f':
            case L'F':
                if(i<argc-1 && readAndValidateCommandLineUlong(argv[i+1], 0, 7, &dwFuzzStage, TRUE)) {
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
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
            case L'l':
            case L'L':
                if(i<argc-1 && !gotFileName) {
                    fileName.append(tstring(argv[i+1]));
                    gotFileName = !fileName.empty();
                    i++;
                }
                else {
                    TPRINT(VERBOSITY_DEFAULT, _T("Parsing error for flag -%c.\n"), argv[i][1]);
                    validUsage = FALSE;
                }
                break;
            default:
                validUsage = FALSE;
                break;
            }
        } // if
        else {
            // If this is the last parameter, it has to be the device name
            if(i==argc-1) {
                deviceName.append(tstring(argv[i]));
                gotDeviceName = !deviceName.empty();
            }
            else {
                validUsage = FALSE;
            }
        }
    } // for
    if(validUsage) {
        // If the only fuzzer is NP fuzzer, skip all ioctl defs related operations
        if (!gotFileName) {
            fileName.append(tstring(L"dibf-bf-results.txt")); // Set default name if not specified
        }
        if(dwFuzzStage!=NP_FUZZER) {
            // Skip reading from file if -i or if only NP fuzzing
            if(!bIgnoreFile) {
                // Attempt to read file
                TPRINT(VERBOSITY_DEFAULT, _T("<<<< CAPTURING IOCTL DEFINITIONS FROM FILE >>>>\n"));
                bIoctls = ReadBruteforceResult();
            }
            // If we don't have the ioctls defs from file
            if(!bIoctls) {
                if(gotDeviceName) {
                    SetConsoleCtrlHandler((PHANDLER_ROUTINE)BruteforceCtrlHandler, TRUE); // Hacky exit for brute force mode
                    // Open the device based on the file name passed from params, fuzz the IOCTLs and return the device handle
                    bIoctls = DoAllBruteForce(dwIOCTLStart, dwIOCTLEnd, bDeepBruteForce);
                    SetConsoleCtrlHandler((PHANDLER_ROUTINE)BruteforceCtrlHandler, FALSE);
                }
                else {
                    TPRINT(VERBOSITY_ERROR, _T("No valid device name provided, exiting\n"));
                }
            }
        }
        else {
            bIoctls = TRUE;
        }
        // At this point we need ioctl defs
        if(bIoctls) {
            FuzzIOCTLs(dwFuzzStage, maxThreads, timeLimits, maxPending, cancelRate);
        }
    } // if validUsage
    else {
        usage();
    }
    return 0;
}

BOOL Dibf::SmartBruteCheck(HANDLE hDevice, DWORD dwIOCTLStart, DWORD dwIOCTLEnd, BOOL bDeepBruteForce)
{
    // Iterate through 5k guesses
    // Map every Error code that gets returned
    // If count == 50, add to banned list
    // TODO: Make variables for guesses etc. Fix up message output stuff.

    DWORD dwIOCTL, lastError, dwIOCTLIndex = 0;
    IoRequest ioRequest(hDevice);  // This unique request gets reused iteratively

    TPRINT(VERBOSITY_INFO, _T("Starting Smart Error Handling\n"))
    for (dwIOCTL = dwIOCTLStart; dwIOCTL <= dwIOCTLEnd; dwIOCTL++) {
        if (dwIOCTL - dwIOCTLStart > 5000){
            break;
        }
        lastError = 0;
        ioRequest.SetIoCode(dwIOCTL);
        if (ioRequest.testSendForValidRequest(bDeepBruteForce, lastError)){
            if (++returnMap[lastError] == 50){
                TPRINT(VERBOSITY_INFO, _T("Adding error to banned list: %#.8x\n"), lastError)
                    bannedErrors.resize(dwIOCTLIndex + 1);
                bannedErrors[dwIOCTLIndex++] = lastError;
            }
        }
    }
    TPRINT(VERBOSITY_INFO, _T("Smart error handling complete\n"))
    return TRUE;
}

BOOL Dibf::IsBanned(DWORD lastError)
{
    BOOL banned = FALSE;
    if (std::find(bannedErrors.begin(), bannedErrors.end(), lastError) != bannedErrors.end()){
        banned = TRUE;
    }
    else{
        banned = FALSE;
    }
    return banned;
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
    DWORD dwIOCTL, lastError, dwIOCTLIndex=0;
    IoRequest ioRequest(hDevice);  // This unique request gets reused iteratively

    for(dwIOCTL=dwIOCTLStart; dwIOCTL<=dwIOCTLEnd; dwIOCTL++) {
        lastError = 0;
        ioRequest.SetIoCode(dwIOCTL);
        if(ioRequest.testSendForValidRequest(bDeepBruteForce, lastError) && !IsBanned(lastError)) {
            if(dwIOCTLIndex<MAX_IOCTLS) {
                ioctls.resize(dwIOCTLIndex+1);
                ioctls[dwIOCTLIndex++].dwIOCTL = dwIOCTL;
            }
            else {
                TPRINT(VERBOSITY_ERROR, _T("Found IOCTL but out of storage space, stopping bruteforce\n"));
                return FALSE;
            }
        }
        if(dwIOCTL % 0x010000 == 0) {
            TPRINT(VERBOSITY_INFO, _T("Current iocode: %#.8x (found %u ioctls so far)\n"), dwIOCTL, dwIOCTLIndex);
        }
        if (userCtrlBreak)
        {
            break;
        }
    }
    TPRINT(VERBOSITY_INFO, _T("Found %u ioctls\n"), dwIOCTLIndex);
    for (IoctlDef iodef : ioctls) {
        TPRINT(VERBOSITY_INFO, _T("IOCTL Found: %#.8x\n"), iodef.dwIOCTL);
    }
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
    userCtrlBreak = FALSE; // Re-set this in case they quit the brute iocode phase but still want buf sizes
    for(IoctlDef &iodef : ioctls) {
        TPRINT(VERBOSITY_INFO, _T(" Working on IOCTL %#.8x\n"), iodef.dwIOCTL);
        // Find lower size edge
        ioRequest.SetIoCode(iodef.dwIOCTL);
        dwCurrentSize = 0;
        while((dwCurrentSize<MAX_BUFSIZE) && !ioRequest.testSendForValidBufferSize(dwCurrentSize)) {
            dwCurrentSize++;
        }
        // If an IOCTL either requires a buffer larger than supported or performs a strict check on the outgoing buffer
        if(dwCurrentSize==MAX_BUFSIZE) {
            TPRINT(VERBOSITY_INFO, _T(" Failed to find lower edge. Skipping.\n"));
            iodef.dwLowerSize = 0;
            iodef.dwUpperSize = MAX_BUFSIZE;
        }
        else {
            TPRINT(VERBOSITY_INFO, _T(" Found lower size edge at %d bytes\n"), dwCurrentSize);
            iodef.dwLowerSize = dwCurrentSize;
            // Find upper size edge
            while((dwCurrentSize<MAX_BUFSIZE) && ioRequest.testSendForValidBufferSize(dwCurrentSize)) {
                dwCurrentSize++;
            }
            TPRINT(VERBOSITY_INFO, _T(" Found upper size edge at %d bytes\n"), dwCurrentSize);
            iodef.dwUpperSize = dwCurrentSize;
        }
        if (userCtrlBreak){
            break;
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
BOOL Dibf::WriteBruteforceResult()
{
    BOOL bResult=FALSE;
    ofstream logFile;

    // Open the log file
    logFile.open((LPCTSTR)fileName);
    if(logFile.good()) {
        logFile << (string&)deviceName << "\n";
        // Write all found ioctls
        for(IoctlDef iodef : ioctls) {
            logFile << std::hex << iodef.dwIOCTL << " " << iodef.dwLowerSize << " " << iodef.dwUpperSize << "\n";
        }
        TPRINT(VERBOSITY_INFO, _T("Successfully written IOCTLs data to log file %s\n"), (LPCTSTR)fileName);
        logFile.close();
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Error creating/opening log file %s\n"), (LPCTSTR)fileName);
    }
    return bResult;
}

//DESCRIPTION:
// Reads all bruteforce resuls from a log file (dibf-bf-results.txt by default).
//OUTPUT:
// Populates deviceName, IOCTLStorage and returns a bool indicating
// if the read was successful or not.
//
BOOL Dibf::ReadBruteforceResult()
{
    BOOL bResult=FALSE;
    ifstream logFile;
    tstring line, deviceNameFromFile;

    // Open the log file
    logFile.open((LPCTSTR)fileName);
    if(logFile.good()) {
        // First, read the device name
        getline(logFile, (string&)deviceNameFromFile);
        if(logFile.good()) {
            // Device name mismatch between file and command line
            if(gotDeviceName) {
                if(deviceNameFromFile!=deviceName) {
                    TPRINT(VERBOSITY_ERROR, _T("Device name from command line (%s) and from existing %s file (%s) differ, aborting\n"), (LPCTSTR)deviceName, (LPCTSTR)fileName, (LPCTSTR)deviceNameFromFile);
                    gotDeviceName = FALSE;
                }
            }
            else {
                deviceName = deviceNameFromFile;
                gotDeviceName = TRUE;
            }
            if(gotDeviceName) {
                // Then read up all the IOCTLs and their size edges
                while(!logFile.eof()) {
                    getline(logFile, (string&)line);
                    if(!line.empty()) {
                        IoctlDef iodef;
                        istringstream stream(line);
                        stream >> std::hex >> iodef.dwIOCTL >> iodef.dwLowerSize>> iodef.dwUpperSize;
                        ioctls.push_back(iodef);
                        TPRINT(VERBOSITY_ALL, _T("Loaded IOCTL %#.8x [%u, %u]\n"), iodef.dwIOCTL, iodef.dwLowerSize, iodef.dwUpperSize);
                    }
                }
                TPRINT(VERBOSITY_DEFAULT, _T("Found and successfully loaded values from %s\n"), (LPCTSTR)fileName);
                TPRINT(VERBOSITY_INFO, _T(" Device name: %s\n"), (LPCTSTR)deviceName);
                TPRINT(VERBOSITY_INFO, _T(" Number of IOCTLs: %d\n"), ioctls.size());
                bResult = TRUE;
            }
        }
        else {
            TPRINT(VERBOSITY_ERROR, _T("Reading device name from log file %s failed.\n"), (LPCTSTR)fileName);
        }
        logFile.close();
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Failed to open Log file %s\n"), (LPCTSTR)fileName);
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
    // If enabled by command line, run sliding DWORD fuzzer
    if(timeLimits[0]&&(dwFuzzStage & DWORD_FUZZER) == DWORD_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, _T("<<<< RUNNING SLIDING DWORD FUZZER >>>>\n"));
        Fuzzer::printDateTime(FALSE);
        SyncFuzzer *syncf = new SyncFuzzer(timeLimits[0], new SlidingDwordFuzzer(ioctls));
        if(syncf->init(deviceName)) {
            syncf->start();
        }
        else {
            TPRINT(VERBOSITY_ERROR, _T("SlidingDWORD fuzzer init failed. Aborting run.\n"));
        }
        delete syncf;
        Fuzzer::tracker.stats.print();
    }
    // If enabled by command line, run pure random fuzzer
    if(timeLimits[1]&&(dwFuzzStage & RANDOM_FUZZER)==RANDOM_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, _T("<<<< RUNNING RANDOM FUZZER >>>>\n"));
        Fuzzer::printDateTime(FALSE);
        AsyncFuzzer *asyncf = new AsyncFuzzer(timeLimits[1], maxPending, cancelRate, new Dumbfuzzer(ioctls));
        if(asyncf->init(deviceName, maxThreads)) {
            asyncf->start();
        }
        else {
            TPRINT(VERBOSITY_ERROR, _T("Dumbfuzzer init failed. Aborting run.\n"));
        }
        delete asyncf;
        Fuzzer::tracker.stats.print();
    }
    // If enabled by command line, run custom fuzzer (taking input from named pipe)
    if(timeLimits[2]&&(dwFuzzStage & NP_FUZZER) == NP_FUZZER) {
        TPRINT(VERBOSITY_DEFAULT, _T("<<<< RUNNING CUSTOM FUZZER >>>>\n"));
        Fuzzer::printDateTime(FALSE);
        AsyncFuzzer *customFuzzer=NULL;
        NamedPipeInputFuzzer *pipef = new NamedPipeInputFuzzer();
        if(pipef->Init()) {
            customFuzzer = new AsyncFuzzer(timeLimits[2], maxPending, cancelRate, pipef);
            if(customFuzzer->init(deviceName, maxThreads)) {
                customFuzzer->start();
            }
            else {
                TPRINT(VERBOSITY_ERROR, _T("Custom fuzzer init failed. Aborting run.\n"));
            }
            delete customFuzzer;
        }
        else {
            TPRINT(VERBOSITY_ERROR, _T("Failed to initialize named pipe fuzzing provider. Aborting run.\n"));
        }
        Fuzzer::tracker.stats.print();
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
    TPRINT(VERBOSITY_DEFAULT, _T("---------------------------------------------------------------------------\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("DIBF - Device IOCTL Bruteforcer and Fuzzer\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("(C)2014-2015 andreas at isecpartners dot com\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("(C)2014-2015 nguigo at isecpartners dot com\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("---------------------------------------------------------------------------\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("Usage:\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" dibf <options> <device name>\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("Options:\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -h You're looking at it\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -i Ignore (OVERWRITE) previous logfile\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -l Specify custom logfile name to read from/write to (default dibf-bf-results.txt)\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -d Deep IOCTL bruteforce (8-9 times slower)\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -v [0-3] Verbosity level\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -s [ioctl] Start IOCTL value\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -e [ioctl] End IOCTL value\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -t [d1,d2,d4] Timeout for each fuzzer in seconds -- no spaces and decimal input ONLY\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" -p [max requests] Max number of async pending requests (loosely enforced, VERBOSITY_DEFAULT %d)\n"), MAX_PENDING);
    TPRINT(VERBOSITY_DEFAULT, _T(" -a [max threads] Max number of threads, VERBOSITY_DEFAULT is 2xNbOfProcessors, max is %d\n"), MAX_THREADS);
    TPRINT(VERBOSITY_DEFAULT, _T(" -c [%% cancelation] Async cancelation attempt percent rate (VERBOSITY_DEFAULT %d)\n"), CANCEL_RATE);
    TPRINT(VERBOSITY_DEFAULT, _T(" -f [0-7] Fuzz flag. OR values together to run multiple\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          fuzzer stages. If left out, it defaults to 0x3\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          stages.\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          0 = Brute-force IOCTLs only\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          1 = Sliding DWORD (sync)\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          2 = Random (async)\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("          4 = Named Pipe (async)\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("Examples:\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" dibf \\\\.\\MyDevice\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" dibf -v -d -s 0x10000000 \\\\.\\MyDevice\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" dibf -f 0x3 \\\\.\\MyDevice\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("Notes:\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" - The bruteforce stage will generate a file named \"dibf-bf-results.txt\"\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("   in the same directory as the executable. If dibf is started with no\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("   arguments, it will look for this file and start the fuzzer with the values\n"));
    TPRINT(VERBOSITY_DEFAULT, _T("   from it. The -l flag can be used to specify a custom results file name.\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" - If not specified otherwise, command line arguments can be passed as decimal or hex (prefix with \"0x\")\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" - CTRL-C interrupts the current stage and moves to the next if any. Current statistics will be displayed.\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" - The statistics are cumulative.\n"));
    TPRINT(VERBOSITY_DEFAULT, _T(" - The command-line flags are case-insensitive.\n"));
}

BOOL __stdcall Dibf::BruteforceCtrlHandler(DWORD fdwCtrlType)
{
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_BREAK_EVENT){
        TPRINT(VERBOSITY_DEFAULT, _T("CTRL_C_EVENT Detected. Exiting BruteForce.\n"));
        userCtrlBreak = TRUE;
    }
    else {
        userCtrlBreak = TRUE;
    }
    return userCtrlBreak;
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
