package run

import (
	"fmt"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

func BofExecute(bofByte []byte, args []string) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Sprintf("Panic occurred when executing BOF: %v", r)
		}
	}()

	// Prefix all args with "z" to indicate string type
	prefixedArgs := make([]string, len(args))
	for i, arg := range args {
		prefixedArgs[i] = "z" + arg
	}

	argsByte, err := lighthouse.PackArgs(prefixedArgs)
	if err != nil {
		return fmt.Sprintf("Error packing arguments: %v", err)
	}

	output, err := coff.Load(bofByte, argsByte)
	if err != nil {
		return fmt.Sprintf("Error loading BOF: %v", err)
	}

	return output
}
