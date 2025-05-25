package execution

import (
	"bytes"
	"fmt"
	"strings"
	"github.com/masterzen/winrm"
)

type PowerShellRemoting struct{}

func (ps PowerShellRemoting) InvokeCommand(computerName, command, domain, username, password string) (string, error) {
	// Configure the WinRM endpoint
	endpoint := winrm.Endpoint{
		Host:    computerName,
		Port:    5985,   
		HTTPS:   false, 
		Insecure: true,
	}

	useCredentials := domain != "" && username != "" && password != ""

	// Initialize WinRM client
	var client *winrm.Client
	var err error

	if useCredentials {
		client, err = winrm.NewClient(&endpoint, fmt.Sprintf("%s\\%s", domain, username), password)
	} else {
		client, err = winrm.NewClient(&endpoint, "", "")
	}

	if err != nil {
		return "", fmt.Errorf("failed to create WinRM client: %v", err)
	}

	// Prepare buffers for output
	var stdout, stderr bytes.Buffer

	// Execute the PowerShell command remotely
	psCmd := fmt.Sprintf("powershell -Command \"%s\"", strings.ReplaceAll(command, "\"", "`\""))
	exitCode, err := client.Run(psCmd, &stdout, &stderr)
	if err != nil {
		return "", fmt.Errorf("failed to execute command: %v", err)
	}

	// Return the appropriate output
	if exitCode != 0 {
		return stderr.String(), nil
	}

	return stdout.String(), nil
}
