// pivots/ad_windows.go
// +build windows

package brute

/*
#include <windows.h>
#include <lm.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func getCurrentDomain() (string, error) {
	var domain *C.CHAR
	var status C.NET_API_STATUS
	
	status = C.NetGetAnyDCName(nil, nil, &domain)
	if status != C.NERR_Success {
		return "", fmt.Errorf("domain detection failed with error: %d", status)
	}
	defer C.NetApiBufferFree(unsafe.Pointer(domain))
	
	return C.GoString(domain), nil
}
