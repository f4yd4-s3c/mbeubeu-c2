package enum

import (
	"fmt"
	"image"
	"image/png"
	"os"

	"github.com/kbinani/screenshot"
)

func RunScreenshot(tempFile string) (string, error) {
	n := screenshot.NumActiveDisplays() // :contentReference[oaicite:0]{index=0}
	if n == 0 {
		return "", fmt.Errorf("no active displays found")
	}

	var allBounds image.Rectangle
	for i := 0; i < n; i++ {
		b := screenshot.GetDisplayBounds(i) // :contentReference[oaicite:1]{index=1}
		allBounds = allBounds.Union(b)
	}

	// Capture that full rectangle
	img, err := screenshot.CaptureRect(allBounds)
	if err != nil {
		return "", fmt.Errorf("failed to capture desktop: %w", err)
	}

	// Save to file
	file, err := os.Create(tempFile)
	if err != nil {
		return "", fmt.Errorf("could not create file %q: %w", tempFile, err)
	}
	defer file.Close()

	if err := png.Encode(file, img); err != nil {
		return "", fmt.Errorf("failed to encode PNG: %w", err)
	}

	fmt.Println("Screenshot saved to:", tempFile)
	return tempFile, nil
}

func DeleteTempFile(tempFile string) {
        err := os.Remove(tempFile)
        if err != nil {
                fmt.Println(err)
                //return err
        }
        fmt.Println("Temporary screenshot deleted")
}

