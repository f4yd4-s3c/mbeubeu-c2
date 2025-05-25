// +build amd64

#include "textflag.h"

// func asmCPUID(buf unsafe.Pointer, op uint32)
// It executes the CPUID instruction with op in EAX and stores the results
// in the 16-byte buffer pointed to by buf.
TEXT ·asmCPUID(SB), NOSPLIT, $0-16
    // Load first parameter (buf pointer) from 0(SP) into DI.
    MOVQ buf+0(SP), DI
    // Load second parameter (op) from 8(SP) into AX.
    MOVL op+8(SP), AX
    CPUID
    // Store results into the buffer pointed by DI.
    MOVL AX, 0(DI)
    MOVL BX, 4(DI)
    MOVL CX, 8(DI)
    MOVL DX, 12(DI)
    RET

