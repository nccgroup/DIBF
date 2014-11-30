#include "stdafx.h"
#include "FuzzingProvider.h"

#define LOW_WORD(DWORD) (DWORD&0xffff)
#define HIGH_WORD(DWORD) ((DWORD&0xffff0000)>>16)

CONST DWORD SlidingDwordFuzzer::DWORDArray[] = {0x0fffffff, 0x10000000, 0x1fffffff, 0x20000000, 0x3fffffff, 0x40000000, 0x7fffffff, 0x80000000, 0xffffffff};

// Empty constructor and destructor
FuzzingProvider::FuzzingProvider()
{
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

BOOL Dumbfuzzer::fuzzRequest(IoRequest *request, std::mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE;
    INT i;
    UINT r;
    DWORD size, ioctlIndex;
    PUCHAR fuzzBuf;

    r = (*threadRandomProvider)();
    // Pick random ioctl def
    ioctlIndex = LOW_WORD(r)%ioStore->count;
    // Set code
    request->SetIoCode(ioStore->ioctls[ioctlIndex].dwIOCTL);
    // Get random size between low and high limits
    size = ioStore->ioctls[ioctlIndex].dwLowerSize+(HIGH_WORD(r)%(ioStore->ioctls[ioctlIndex].dwUpperSize-ioStore->ioctls[ioctlIndex].dwLowerSize));
    bResult = request->allocBuffers(size, DEFAULT_OUTLEN);
    if(bResult) {
        // Get input buffer pointer (TODO: FIX THIS BAD OOP DESIGN)
        fuzzBuf = request->getInbuf();
        for(i=0; i<(INT)(size-sizeof(INT)); i+=sizeof(INT)) {
            *(PUINT)(&fuzzBuf[i]) = (*threadRandomProvider)();
        }
        // Last DWORD
        r = (*threadRandomProvider)();
        for(INT j=0; i<(INT)size; i++,j+=8) {
            fuzzBuf[i] = (UCHAR)((r>>j)&0xff);
        }
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

BOOL SlidingDwordFuzzer::fuzzRequest(IoRequest *request, std::mt19937 *threadRandomProvider)
{
    BOOL bResult=FALSE, retry=TRUE;
    DWORD size;
    PUCHAR fuzzBuf, pCurrentPosition;

    UNREFERENCED_PARAMETER(threadRandomProvider);

    while(retry) {
        // Check for ioctls exhaustion
        if(ioctlIndex<ioStore->count-1) {
            // Check that we have another DWORD to try sliding
            if(iteration<_countof(DWORDArray)-1) {
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
        // Set code
        request->SetIoCode(ioStore->ioctls[ioctlIndex].dwIOCTL);
        // Get max size for this ioctl
        size = ioStore->ioctls[ioctlIndex].dwUpperSize;
        // Alloc buffers
        bResult = request->allocBuffers(size, DEFAULT_OUTLEN);
        if(bResult) {
            fuzzBuf = request->getInbuf();
            pCurrentPosition = fuzzBuf+position;
            ZeroMemory(fuzzBuf, size);
            *((DWORD*)pCurrentPosition) = DWORDArray[iteration];
        }
        // Iterating
        position += sizeof(DWORD);
    }
    return bResult;
}