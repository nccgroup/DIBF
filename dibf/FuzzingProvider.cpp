#include "stdafx.h"
#include "FuzzingProvider.h"

Dumbfuzzer::Dumbfuzzer(IoctlStorage* ioctlStorage) : ioStore(ioctlStorage)
{
    // Init PRNG seed
    TPRINT(LEVEL_ALWAYS_PRINT, L"Dumb PRNG initiated\n");
    srand((UINT)0x9c3a168f^GetTickCount());
    return;
}

Dumbfuzzer::~Dumbfuzzer() {}

BOOL Dumbfuzzer::fuzzRequest(IoRequest *request) {

    BOOL bResult=FALSE;
    DWORD size, ioctlIndex;
    PUCHAR fuzzBuf;

    // Pick random ioctl def
    ioctlIndex = rand()%ioStore->count;
    // Set code
    request->SetIoCode(ioStore->ioctls[ioctlIndex].dwIOCTL);
    // Get random sizes between low and high limits
    size = ioStore->ioctls[ioctlIndex].dwLowerSize+(rand()%(ioStore->ioctls[ioctlIndex].dwUpperSize-ioStore->ioctls[ioctlIndex].dwLowerSize));
    bResult = request->allocBuffers(size, DEFAULT_OUTLEN);
    if(bResult) {
        // Get input buffer pointer (TODO: FIX THIS BAD OOP DESIGN)
        fuzzBuf=request->getInbuf();
        for(UINT i=0; i<size; i++) {
            fuzzBuf[i] = (UCHAR)(rand()&0xff);
        }
    }
    else {
        // TODO: remove this
        bResult = FALSE;
    }
    return bResult;
}
