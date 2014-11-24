#include "stdafx.h"
#include "FuzzingProvider.h"

#define LOW_WORD(DWORD) (DWORD&0xffff)
#define HIGH_WORD(DWORD) ((DWORD&0xffff0000)>>16)

// Empty constructor and destructor
FuzzingProvider::FuzzingProvider() {}
FuzzingProvider::~FuzzingProvider() {}

Dumbfuzzer::Dumbfuzzer(IoctlStorage* ioctlStorage) : ioStore(ioctlStorage)
{
    // Init PRNG seed
    srand((UINT)0x9c3a168f^GetTickCount());
    return;
}

Dumbfuzzer::~Dumbfuzzer() {}

BOOL Dumbfuzzer::fuzzRequest(IoRequest *request, std::mt19937 *threadRandomProvider)
{

    BOOL bResult=FALSE;
    INT i, r;
    DWORD size, ioctlIndex;
    PUCHAR fuzzBuf;

    r = (*threadRandomProvider)();
    // Pick random ioctl def
    ioctlIndex = LOW_WORD(r)%ioStore->count;
    // Set code
    request->SetIoCode(ioStore->ioctls[ioctlIndex].dwIOCTL);
    // Get random sizes between low and high limits
    size = ioStore->ioctls[ioctlIndex].dwLowerSize+(HIGH_WORD(r)%(ioStore->ioctls[ioctlIndex].dwUpperSize-ioStore->ioctls[ioctlIndex].dwLowerSize));
    bResult = request->allocBuffers(size, DEFAULT_OUTLEN);
    if(bResult) {
        // Get input buffer pointer (TODO: FIX THIS BAD OOP DESIGN)
        fuzzBuf=request->getInbuf();
        for(i=0; i<(INT)(size-sizeof(INT)); i+=sizeof(INT)) {
            *(PUINT)(&fuzzBuf[i]) = (*threadRandomProvider)();
        }
        // Last DWORD
        r = (*threadRandomProvider)();
        for(UINT j=0; i<size; i++,j+=8) {
            fuzzBuf[i] = (UCHAR)((r>>j)&0xff);
        }
    }
    return bResult;
}
