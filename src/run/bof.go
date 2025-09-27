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

	// Build type string (e.g., "zzz" for 3 string args)
	types := ""
	for range args {
		types += "z"
	}

	// Convert args to []interface{}
	values := make([]interface{}, len(args))
	for i, arg := range args {
		values[i] = arg // Ensure values are interface{} types
	}

	argsByte, err := lighthouse.PackArgs(types, values)
	if err != nil {
		return fmt.Sprintf("Error packing arguments: %v", err)
	}

	output, err := coff.Load(bofByte, argsByte)
	if err != nil {
		return fmt.Sprintf("Error loading BOF: %v", err)
	}

	return output
}

