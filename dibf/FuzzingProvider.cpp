#include "stdafx.h"
#include "FuzzingProvider.h"

#define LOW_WORD(DWORD) (DWORD&0xffff)
#define HIGH_WORD(DWORD) ((DWORD&0xffff0000)>>16)

CONST DWORD SlidingDwordFuzzer::DWORDArray[] = {0x0fffffff, 0x10000000, 0x1fffffff, 0x20000000, 0x3fffffff, 0x40000000, 0x7fffffff, 0x80000000, 0xffffffff};

// Empty constructor and destructor
FuzzingProvider::FuzzingProvider() : canGoCold(FALSE)
{
    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    TPRINT(VERBOSITY_DEBUG, L"FuzzingProvider constructor\n");
    return;
}
FuzzingProvider::~FuzzingProvider()
{
    TPRINT(VERBOSITY_DEBUG, L"FuzzingProvider destructor\n");
    return;
}

Dumbfuzzer::Dumbfuzzer(IoctlStorage* ioctlStorage) : ioStore(ioctlStorage)
{
    TPRINT(VERBOSITY_DEBUG, L"Dumbfuzzer constructor\n");
    return;
}

Dumbfuzzer::~Dumbfuzzer()
{
    TPRINT(VERBOSITY_DEBUG, L"Dumbfuzzer destructor\n");
    return;
}

BOOL Dumbfuzzer::GetRandomIoctlAndBuffer(PDWORD iocode, vector<UCHAR> **output, mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE;
    INT i;
    UINT r;
    DWORD size, ioctlIndex;
    vector<UCHAR> *fuzzBuf;

    r = (*threadRandomProvider)();
    // Pick random ioctl def
    ioctlIndex = LOW_WORD(r)%ioStore->count;
    // Get random size between low and high limits
    size = ioStore->ioctls[ioctlIndex].dwLowerSize+(HIGH_WORD(r)%(ioStore->ioctls[ioctlIndex].dwUpperSize-ioStore->ioctls[ioctlIndex].dwLowerSize));
    fuzzBuf = new vector<UCHAR>(size);
    if(fuzzBuf) {
        for(i=0; i<(INT)(size-sizeof(INT)); i+=sizeof(INT)) {
            *(PUINT)(&(*fuzzBuf)[i]) = (*threadRandomProvider)();
        }
        // Last DWORD
        r = (*threadRandomProvider)();
        for(INT j=0; i<(INT)size; i++,j+=8) {
            (*fuzzBuf)[i] = (UCHAR)((r>>j)&0xff);
        }
        // Set code
        *iocode = ioStore->ioctls[ioctlIndex].dwIOCTL;
        *output = fuzzBuf;
        bResult = TRUE;
    }
    return bResult;
}

SlidingDwordFuzzer::SlidingDwordFuzzer(IoctlStorage* ioctlStorage) : ioStore(ioctlStorage), iteration(0), position(0), ioctlIndex(0)
{
    TPRINT(VERBOSITY_DEBUG, L"SlidingDwordFuzzer constructor\n");
    return;
}

SlidingDwordFuzzer::~SlidingDwordFuzzer()
{
    TPRINT(VERBOSITY_DEBUG, L"SlidingDwordFuzzer destructor\n");
    return;
}

BOOL SlidingDwordFuzzer::GetRandomIoctlAndBuffer(PDWORD iocode, vector<UCHAR> **output, mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE, retry=TRUE;
    DWORD size;
    vector<UCHAR> *fuzzBuf;
    PUCHAR pCurrentPosition;

    UNREFERENCED_PARAMETER(threadRandomProvider);

    while(retry) {
        // Check for ioctls exhaustion
        if(ioctlIndex<ioStore->count) {
            // Check that we have another DWORD to try sliding
            if(iteration<_countof(DWORDArray)) {
                // Check that we have room in this buffer
                if(position<ioStore->ioctls[ioctlIndex].dwUpperSize-sizeof(DWORD)) {
                    // exit and fuzz
                    bResult = TRUE;
                    retry = FALSE;
                }
                // Out of room in buffer
                else {
                    iteration++; // Reset DWORD selection
                    position = 0; // Reset position
                }
            }
            // Out of DWORDS
            else {
                ioctlIndex++; // Go to next ioctl
                iteration = 0; // Reset DWORD selection
                position = 0; // Reset position
            }
        }
        else {
            // out of ioctls: all done, exit with bResult false
            retry = FALSE;
        }
    }
    // bResult indicates we have all we need to fuzz
    if(bResult) {
        // Reset return value
        bResult = FALSE;
        // Get max size for this ioctl
        size = ioStore->ioctls[ioctlIndex].dwUpperSize;
        // Alloc buffers
        fuzzBuf = new vector<UCHAR>(size);
        pCurrentPosition = fuzzBuf->data()+position;
        *((DWORD*)pCurrentPosition) = DWORDArray[iteration];
        // Set code
        *iocode = ioStore->ioctls[ioctlIndex].dwIOCTL;
        *output = fuzzBuf;
        bResult = TRUE;
        // Iterating
        position++;
    }
    return bResult;
}

NamedPipeInputFuzzer::NamedPipeInputFuzzer()
{
    canGoCold =TRUE;
    TPRINT(VERBOSITY_DEBUG, L"NamedPipeInputFuzzer constructor\n");
    InitializeCriticalSection(&lock);
    return;
}

BOOL NamedPipeInputFuzzer::Init()
{
    BOOL bResult=FALSE;

    dibf_pipe = CreateNamedPipe(L"\\\\.\\pipe\\dibf_pipe",
                                PIPE_ACCESS_INBOUND,
                                PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
                                1,
                                MAX_BUFSIZE/2,
                                MAX_BUFSIZE/2,
                                0,
                                NULL);
    if(dibf_pipe!=INVALID_HANDLE_VALUE) {
        TPRINT(VERBOSITY_INFO, L"Named pipe created, waiting for connection...\n");
        if(ConnectNamedPipe(dibf_pipe, NULL)?TRUE:(GetLastError()==ERROR_PIPE_CONNECTED)) {
            TPRINT(VERBOSITY_INFO, L"Fuzzing client connected to named pipe\n");
            inputThread = CreateThread(NULL, 0, FuzzInputProc, this, 0, NULL);
            if(inputThread) {
                bResult = TRUE;
            }
            else {
                TPRINT(VERBOSITY_ERROR, L"Failed to create fuzz input thread with error %#.8x\n", GetLastError());
            }
        }
    }
    return bResult;
}

NamedPipeInputFuzzer::~NamedPipeInputFuzzer()
{
    TPRINT(VERBOSITY_DEBUG, L"NamedPipeInputFuzzer destructor\n");
    DeleteCriticalSection(&lock);
    if(dibf_pipe!=INVALID_HANDLE_VALUE) {
        CloseHandle(dibf_pipe);
    }
    CloseHandle(inputThread);
    return;
}

DWORD WINAPI NamedPipeInputFuzzer::FuzzInputProc(PVOID param)
{
    BOOL bDone, bExit=FALSE, bResult=FALSE;
    UCHAR input[MAX_BUFSIZE+4];
    UINT index;
    DWORD bytesRead, error;
    vector<UCHAR> *packet;
    NamedPipeInputFuzzer *npif = (NamedPipeInputFuzzer*)param;

    // Double while is not as bad as it looks
    while(!bExit) {
        index = 0;
        bDone = FALSE;
        while(!bDone) {
            bResult = ReadFile(npif->dibf_pipe, &input[index], (MAX_BUFSIZE+4)-index, &bytesRead, NULL);
            // Check for data reception
            if (bResult&&bytesRead) {
                // Update index
                index+=bytesRead;
                // Sanity check received data
                if(index>=4) {
                    // Create new packet
                    packet = new vector<UCHAR>(input, &input[index]);
                    // Enqueue new packet
                    EnterCriticalSection(&npif->lock);
                    npif->iopackets.push(packet);
                    LeaveCriticalSection(&npif->lock);
                }
                bDone = TRUE;
            }
            else {
                error = GetLastError();
                switch(error) {
                case ERROR_BROKEN_PIPE:
                    TPRINT(VERBOSITY_ERROR, L"Named pipe client disconnected\n");
                    bDone = TRUE;
                    bExit = TRUE;
                    break;
                case ERROR_MORE_DATA:
                    if(bytesRead) {
                        // Update index
                        index+=bytesRead;
                    }
                    else {
                        // Packet too big
                        bDone = TRUE;
                    }
                    break;
                default:
                    TPRINT(VERBOSITY_ERROR, L"Reading from named pipe failed with error %#.8x\n", error);
                    bDone = TRUE;
                    break;
                }
            }
        }
    }
    SetEvent(npif->hEvent);
    return ERROR_SUCCESS;
}

BOOL NamedPipeInputFuzzer::GetRandomIoctlAndBuffer(PDWORD iocode, vector<UCHAR> **output, mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE;
    vector<UCHAR> *packet=NULL;

    UNREFERENCED_PARAMETER(threadRandomProvider);

    EnterCriticalSection(&lock);
    if(!iopackets.empty()) {
        packet = iopackets.front();
        iopackets.pop();
        bResult = TRUE;
    }
    LeaveCriticalSection(&lock);
    if(bResult) {
        // Parse io packet (last 4 bytes is ioctl code)
        *iocode = *(PDWORD)&(packet->data()[packet->size()-sizeof(DWORD)]);
        packet->resize(packet->size()-sizeof(DWORD));
        *output = packet;
    }
    return bResult;
}
