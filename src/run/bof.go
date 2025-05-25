package run

import (
	"fmt"

	"github.com/praetorian-inc/goffloader/src/coff"
)

func BofExecute(bofByte, argsByte []byte) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Sprintf("Panic occurred when executing BOF: %v", r)
		}
	}()

	output, err := coff.Load(bofByte, argsByte)
	if err != nil {
		return fmt.Sprintf("Error loading BOF: %v", err)
	}

	return output
}
