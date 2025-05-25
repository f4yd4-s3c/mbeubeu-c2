// +build 386

#include "textflag.h"

// func asmCPUID(buf *[4]uint32, op uint32)
// Executes the CPUID instruction with 'op' in EAX and stores the results
// in the 4-element array pointed to by buf.
TEXT ·asmCPUID(SB), NOSPLIT, $0-8
    MOVL buf+0(FP), DI   // Load buf pointer into DI
    MOVL op+4(FP), AX    // Load op into AX
    CPUID
    MOVL AX, 0(DI)       // Store EAX at buf[0]
    MOVL BX, 4(DI)       // Store EBX at buf[1]
    MOVL CX, 8(DI)       // Store ECX at buf[2]
    MOVL DX, 12(DI)      // Store EDX at buf[3]
    RET

