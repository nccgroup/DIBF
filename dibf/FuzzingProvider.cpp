#include "stdafx.h"
#include "FuzzingProvider.h"

#define LOW_WORD(DWORD) (DWORD&0xffff)
#define HIGH_WORD(DWORD) ((DWORD&0xffff0000)>>16)

CONST DWORD SlidingDwordFuzzer::DWORDArray[] = {0x0fffffff, 0x10000000, 0x1fffffff, 0x20000000, 0x3fffffff, 0x40000000, 0x7fffffff, 0x80000000, 0xffffffff};

// Empty constructor and destructor
FuzzingProvider::FuzzingProvider() : canGoCold(FALSE)
{
    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    TPRINT(VERBOSITY_DEBUG, _T("FuzzingProvider constructor\n"));
    return;
}
FuzzingProvider::~FuzzingProvider()
{
    TPRINT(VERBOSITY_DEBUG, _T("FuzzingProvider destructor\n"));
    return;
}

Dumbfuzzer::Dumbfuzzer(const vector<IoctlDef> &ioctlStorage) : ioStore(ioctlStorage)
{
    TPRINT(VERBOSITY_DEBUG, _T("Dumbfuzzer constructor\n"));
    return;
}

Dumbfuzzer::~Dumbfuzzer()
{
    TPRINT(VERBOSITY_DEBUG, _T("Dumbfuzzer destructor\n"));
    return;
}

BOOL Dumbfuzzer::GetRandomIoctlAndBuffer(DWORD &iocode, vector<UCHAR> &output, mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE;
    INT i=0;
    UINT r;
    DWORD size=0, ioctlIndex;

    r = (*threadRandomProvider)();
    // Pick random ioctl def
    ioctlIndex = LOW_WORD(r)%ioStore.size();
    // Get random size between low and high limits (prevent divide by zero)
    if(ioStore[ioctlIndex].dwUpperSize-ioStore[ioctlIndex].dwLowerSize) {
        size = ioStore[ioctlIndex].dwLowerSize+(HIGH_WORD(r)%(ioStore[ioctlIndex].dwUpperSize-ioStore[ioctlIndex].dwLowerSize));
    }
    // If the sizes are equal, take the upper size
    else if(ioStore[ioctlIndex].dwUpperSize == ioStore[ioctlIndex].dwLowerSize){
        size = ioStore[ioctlIndex].dwUpperSize;
    }
    output.resize(size);
    if(size>4) {
        for(i=0; i<(INT)(size-sizeof(INT)); i+=sizeof(INT)) {
            *(PUINT)(&(output)[i]) = (*threadRandomProvider)();
        }
    }
    // Last DWORD
    r = (*threadRandomProvider)();
    for(INT j=0; i<(INT)size; i++,j+=8) {
        output[i] = (UCHAR)((r>>j)&0xff);
    }
    // Every once in awhile, shove the size in the first DWORD of buffer
    if (!(r % SHOVE_LENGTH_FREQ) && size > sizeof(DWORD)) {
        *(PDWORD)(&(output)[0]) = size;
    }
    // Set code
    iocode = ioStore[ioctlIndex].dwIOCTL;
    bResult = TRUE;
    return bResult;
}

SlidingDwordFuzzer::SlidingDwordFuzzer(const vector<IoctlDef> &ioctlStorage) : ioStore(ioctlStorage), iteration(0), position(0), ioctlIndex(0)
{
    TPRINT(VERBOSITY_DEBUG, _T("SlidingDwordFuzzer constructor\n"));
    return;
}

SlidingDwordFuzzer::~SlidingDwordFuzzer()
{
    TPRINT(VERBOSITY_DEBUG, _T("SlidingDwordFuzzer destructor\n"));
    return;
}

BOOL SlidingDwordFuzzer::GetRandomIoctlAndBuffer(DWORD &iocode, vector<UCHAR> &output, mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE, retry=TRUE;
    DWORD size;
    PUCHAR pCurrentPosition;

    UNREFERENCED_PARAMETER(threadRandomProvider);

    while(retry) {
        // Check for ioctls exhaustion
        if(ioctlIndex<ioStore.size()) {
            // Check that we have another DWORD to try sliding
            if(iteration<_countof(DWORDArray)) {
                // Check that we have room in this buffer
                if(position<ioStore[ioctlIndex].dwUpperSize-sizeof(DWORD)) {
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
        size = ioStore[ioctlIndex].dwUpperSize;
        // Alloc buffers
        output.resize(size);
        fill(output.begin(), output.end(), 0);
        pCurrentPosition = output.data()+position;
        *((DWORD*)pCurrentPosition) = DWORDArray[iteration];
        // Set code
        iocode = ioStore[ioctlIndex].dwIOCTL;
        bResult = TRUE;
        // Iterating
        position++;
    }
    return bResult;
}

NamedPipeInputFuzzer::NamedPipeInputFuzzer() : bExit(FALSE)
{
    canGoCold =TRUE;
    TPRINT(VERBOSITY_DEBUG, _T("NamedPipeInputFuzzer constructor\n"));
    InitializeCriticalSection(&lock);
    return;
}

BOOL NamedPipeInputFuzzer::Init()
{
    BOOL bResult=FALSE;

    dibf_pipe = CreateNamedPipe(_T("\\\\.\\pipe\\dibf_pipe"),
                                PIPE_ACCESS_INBOUND,
                                PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
                                1,
                                MAX_BUFSIZE/2,
                                MAX_BUFSIZE/2,
                                0,
                                NULL);
    if(dibf_pipe!=INVALID_HANDLE_VALUE) {
        TPRINT(VERBOSITY_DEFAULT, _T("Named pipe created, waiting for connection...\n"));
        if(ConnectNamedPipe(dibf_pipe, NULL)?TRUE:(GetLastError()==ERROR_PIPE_CONNECTED)) {
            TPRINT(VERBOSITY_DEFAULT, _T("Fuzzing client connected to named pipe\n"));
            inputThread = CreateThread(NULL, 0, FuzzInputProc, this, 0, NULL);
            if(inputThread) {
                bResult = TRUE;
            }
            else {
                TPRINT(VERBOSITY_ERROR, _T("Failed to create fuzz input thread with error %#.8x\n"), GetLastError());
            }
        }
    }
    return bResult;
}

NamedPipeInputFuzzer::~NamedPipeInputFuzzer()
{
    DWORD waitResult;

    TPRINT(VERBOSITY_DEBUG, _T("NamedPipeInputFuzzer destructor\n"));
    bExit = TRUE;

    // Wait 2 seconds then kill the input thread
    waitResult = WaitForSingleObject(inputThread, 2000);
    if(waitResult!=WAIT_OBJECT_0) {
        TerminateThread(inputThread, 0);
    }
    DeleteCriticalSection(&lock);
    if(dibf_pipe!=INVALID_HANDLE_VALUE) {
        CloseHandle(dibf_pipe);
    }
    CloseHandle(inputThread);
    return;
}

DWORD WINAPI NamedPipeInputFuzzer::FuzzInputProc(PVOID param)
{
    BOOL bDone, bResult=FALSE;
    UCHAR input[MAX_BUFSIZE+4];
    UINT index;
    DWORD bytesRead, error;
    vector<UCHAR> *packet;
    NamedPipeInputFuzzer *npif = (NamedPipeInputFuzzer*)param;

    // Double while is not as bad as it looks
    while(!npif->bExit) {
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
                    TPRINT(VERBOSITY_ERROR, _T("Named pipe client disconnected\n"));
                    bDone = TRUE;
                    npif->bExit = TRUE;
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
                    TPRINT(VERBOSITY_ERROR, _T("Reading from named pipe failed with error %#.8x\n"), error);
                    bDone = TRUE;
                    break;
                }
            }
        }
    }
    SetEvent(npif->hEvent);
    return ERROR_SUCCESS;
}

BOOL NamedPipeInputFuzzer::GetRandomIoctlAndBuffer(DWORD &iocode, vector<UCHAR> &output, mt19937 *threadRandomProvider)
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
        iocode = *(PDWORD)&(packet->data()[packet->size()-sizeof(DWORD)]);
        packet->resize(packet->size()-sizeof(DWORD));
        output = *packet; // TODO: avoid this copy
    }
    return bResult;
}
