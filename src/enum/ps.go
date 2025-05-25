package enum

import (
    "fmt"
    "os"
    "strings"

    "github.com/shirou/gopsutil/v3/process"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)


func ListProc() string {
	var builder strings.Builder

	avProcesses := []string{
		"msmpeng.exe", "avp.exe", "windefend.exe", "savservice.exe",
		"avg.exe", "avgsvc.exe", "avguard.exe", "eset.exe", "wrsa.exe",
		"symantec", "norton", "kaspersky", "defender",
		"crowdstrike", "carbonblack", "sentinelone", "s1agent.exe",
		"sysmon.exe",
	}

	currentPid := int32(os.Getpid())

	procs, err := process.Processes()
	if err != nil {
		return fmt.Sprintf("%s[-] Error listing processes: %v%s\n", colorRed, err, colorReset)
	}

	for _, p := range procs {
		pid := p.Pid
		name, err := p.Name()
		if err != nil {
			continue
		}

		nameLower := strings.ToLower(name)
		isAV := false
		for _, av := range avProcesses {
			if strings.Contains(nameLower, av) {
				isAV = true
				break
			}
		}

		if pid == currentPid {
			builder.WriteString(fmt.Sprintf("%s[*] PID: %d\tName: %s (Current)%s\n", colorGreen, pid, name, colorReset))
		} else if isAV {
			builder.WriteString(fmt.Sprintf("%s[!] PID: %d\tName: %s (AV/EDR)%s\n", colorRed, pid, name, colorReset))
		} else {
			builder.WriteString(fmt.Sprintf("    PID: %d\tName: %s\n", pid, name))
		}
	}

	return builder.String()
}

