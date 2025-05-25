package commands

import (
	"fmt"
	"strings"
	"github.com/chzyer/readline"
)

const (
        colorReset  = "\033[0m"
        colorGray  = "\033[37m"
        colorBlue   = "\033[34m"
        colorCyan   = "\033[36m"
        colorYellow = "\033[33m"
        colorGreen  = "\033[32m"
        colorRed    = "\033[31m"
        colorBlack  = "\033[92m"
        boldText    = "\033[1m"
)


func HelpMenu() {
	menu := fmt.Sprintf(`
%s[+] Main Commands:%s
=================
  %slcmd%s                          - Execute local command
  %slist%s                          - List all connected bayefall
  %sremove_bf%s                     - Remove bayefall 
  %sinteract <Bayefall Name>%s      - Start interactive session with bayefall
  %sgenerate_ndobin <-h>%s          - Generate Ndobin Payloads default: exe/bin/ps1.Use -p flag to generate elf payloads for linux
  %sone_liner [-help]%s             - Generate PowerShell oneliner 
  
%s[+] Listener Management:%s
=======================
  %slistener generate <flags>%s     - Create new listener (http/https/quic/soap/tcp)
  %slistener start -n <name>%s      - Start registered listener
  %slistener stop -n <name>%s       - Stop running listener
  %slistener delete -n <name>%s     - Remove listener configuration
  %slistener show%s                 - Display all listeners

%s[+] Windows Task/Ndigeul Commands:%s
==================================
  %ssleep <second>%s               - Time to sleep default 5
  %sjitter <second>%s              - Jitter default 0	
  %sshell <command>%s              - Execute Shell command
  %spwsh <command>%s               - Execute PowerShell command
  %spwsh-bypass <command>%s        - Bypass AMSI/ETW with PowerShell
  %sps%s                           - List running processes
  %sbof_execute%s                  - Execute beacon object file
  %skill -y%s                      - Terminate bayefall process
  %ssc-spawn <.bin_Path>%s         - Shellcode injection
  %sls [path]%s                    - List directory contents
  %scd <path>%s                    - Change current directory  
  %swhoami%s                       - Print current user
  %spwd%s                          - Print working directory
  %scat <file>%s                   - Display file contents
  %sdownload <remote> [local]%s    - Download file from bayefall
  %supload  <local> [remote]%s     - Upload file to bayefall
  %shashdump%s                     - Dump SAM hashes
  %srunas <user> <pass> <cmd>%s    - Execute as different user
  %swinrm <target> <command>%s     - Execute via WinRM
  %sjump-psexec <target>%s         - Lateral move via PSExec. Example: jump-psexec srv01.lab01.local https_listener 
  %sdefence-analysis%s             - Defense analysis
  %sinfo%s                         - Get system information
  %sGet-*/Set-*%s                  - *SharpView commands
  %sList-Drivers%s                 - Enumerate loaded drivers
  %sexecute-assembly <path>%s      - Execute .NET assembly in-memory
  %smaketoken <flags>%s            - Create impersonation token
  %sgetprivs%s                     - Enable privileges
  %srevtoself%s                    - Revert to original token
  %soffice_infect <path>%s         - Inject VBA into Office docs. Example: office_infect /local/path/to/vbaProject.bin
  %susb_infect%s                   - Create malicious USB trigger. Example: usb_infect Ndobin.exe invoice.docx NoSuspectName 60
  %ssocks <addr> <port>%s          - Start SOCKS5 proxy
  %sstop-socks%s                   - Terminate SOCKS proxy
  %sscreenshot%s                   - Capture desktop screenshot
  %ssmart_shot%s                   - Stealth screenshot capture. Example: smart_shot titles.txt 5000
  %spwsh-import <script>%s         - Import PowerShell module
  %spwsh-execute <command>%s       - Execute imported module command
  %spwsh-bypass%s                  - Run powershell command tat bypass amsi and etw.
  %spersist_startup%s              - Startup persistence
  %spersist_registryrun%s          - Registry run persistence
  %spersist_schtask%s              - Scheduled task persistence
  %spersist_winlogon%s             - Winlogon persistence
  %slcmd%s                         - Execute local command
  %shelp%s                         - Show this help message

  %s[+] Linux Task/Ndigeul Commands:%s
  ==================================
  %ssleep <second>%s               - Time to sleep default 5
  %sjitter <second>%s              - Jitter default 0   
  %sshell <command>%s              - Execute Bash command
  %sps%s                           - List running processes
  %skill -y%s                      - Terminate bayefall process
  %sls [path]%s                    - List directory contents
  %scd <path>%s                    - Change current directory
  %swhoami%s                       - Print current user
  %spwd%s                          - Print working directory
  %scat <file>%s                   - Display file contents
  %sdownload <remote> [local]%s    - Download file from bayefall
  %supload  <local> [remote]%s     - Upload file to bayefall
  %slcmd%s                         - Execute local command
  %shelp%s                         - Show this help message

`,
		// Main Commands
		colorBlue, colorReset,
		colorCyan, colorReset, // lcmd
		colorCyan, colorReset, // list
		colorCyan, colorReset, // remove_bf
		colorCyan, colorReset, // interact
		colorCyan, colorReset, // generate_ndobin
		colorCyan, colorReset, // one_liner
		
		// Listener Management
		colorBlue, colorReset,
		colorCyan, colorReset, // listener generate
		colorCyan, colorReset, // listener start
		colorCyan, colorReset, // listener stop
		colorCyan, colorReset, // listener delete
		colorCyan, colorReset, // listener show
		
		// Task Commands Header
		colorBlue, colorReset,
		
		// All task commands
		colorCyan, colorReset, // sleep
		colorCyan, colorReset, // jitter
		colorCyan, colorReset, // shell
		colorCyan, colorReset, // pwsh
		colorCyan, colorReset, // ps
		colorCyan, colorReset, // bof
		colorCyan, colorReset, // kill
		colorCyan, colorReset, // spawn
		colorCyan, colorReset, // ls
		colorCyan, colorReset, // cd
		colorCyan, colorReset, // whoami
		colorCyan, colorReset, // pwd
		colorCyan, colorReset, // cat
		colorCyan, colorReset, // download
		colorCyan, colorReset, // uploadf
		colorCyan, colorReset, // hashdump
		colorCyan, colorReset, // GigiSamDump
		colorCyan, colorReset, // runas
		colorCyan, colorReset, // winrm
		colorCyan, colorReset, // jump-psexec
		colorCyan, colorReset, // da
		colorCyan, colorReset, // info
		colorCyan, colorReset, // Get-*
		colorCyan, colorReset, // List-Drivers
		colorCyan, colorReset, // execute-assembly
		colorCyan, colorReset, // maketoken
		colorCyan, colorReset, // getprivs
		colorCyan, colorReset, // revtoself
		colorCyan, colorReset, // office_infect
		colorCyan, colorReset, // usb_infect
		colorCyan, colorReset, // socks
		colorCyan, colorReset, // stop-socks
		colorCyan, colorReset, // screenshot
		colorCyan, colorReset, // smart_shot
		colorCyan, colorReset, // pimport
		colorCyan, colorReset, // pexecute
		colorCyan, colorReset, // pwsh-bypass
		colorCyan, colorReset, //persist
		colorCyan, colorReset, //persist
		colorCyan, colorReset, //persist
		colorCyan, colorReset, //persist
		colorCyan, colorReset, // lcmd
		colorCyan, colorReset, // help

		//Linux Task
		colorBlue, colorReset, //Linux Tasks
		colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
                colorCyan, colorReset, 
		colorCyan, colorReset, //lcmd
		colorCyan, colorReset,

	)

	fmt.Println(menu)
}


var AutoCompleteCommands = []string{
    // Core commands
    "back",
    "exit",
    "help",
    "clear",
    //"history",
    "kill",
    "lcmd",

    //shell command
    "shell",
    "pwsh",
    "sleep",
    "jitter",
    "pwsh-bypass",
    "pwd",
    "ls",
    "cat",
    "whoami",
    "ps",
    
    // File operations
    "download",
    "upload",
    "List-Drivers",
    "office_infect",
    "usb_infect",
    "defence-analysis",
    
    // Credential commands
    "maketoken",
    "mimikatz_samdump",
    "revtoself",
    "pth",
    "hashdump",
    
    // Execution commands
    "execute-assembly",
    "runas",
    "sc-spawn",
    "jump-psexec",
    "bof_execute",
    "pwsploit",
    "pwsh-execute",
    "pwsh-import",
    "winrm",
    "persist_startup",
    "persist_resgistryrun",
    "persist_schtask",
    "persist_winlogon",
    
    // Recon commands
    "screenshot",
    "audio_record",
    "smart_shot",
    "port_scan",
    
    // Network operations
    "socks",
    
    // SharpView commands
    /*
    "Get-DomainGPOUserLocalGroupMapping",
    "Find-GPOLocation",
    "Get-DomainGPOComputerLocalGroupMapping",
    "Find-GPOComputerAdmin",
    "Get-DomainObjectAcl",
    "Get-ObjectAcl",
    "Add-DomainObjectAcl",
    "Add-ObjectAcl",
    "Remove-DomainObjectAcl",
    "Get-RegLoggedOn",
    "Get-LoggedOnLocal",
    "Get-NetRDPSession",
    "Test-AdminAccess",
    "Invoke-CheckLocalAdminAccess",
    "Get-WMIProcess",
    "Get-NetProcess",
    "Get-WMIRegProxy",
    "Get-Proxy",
    "Get-WMIRegLastLoggedOn",
    "Get-LastLoggedOn",
    "Get-WMIRegCachedRDPConnection",
    "Get-CachedRDPConnection",
    "Get-WMIRegMountedDrive",
    "Get-RegistryMountedDrive",
    "Find-InterestingDomainAcl",
    "Invoke-ACLScanner",
    "Get-NetShare",
    "Get-NetLoggedon",
    "Get-NetLocalGroup",
    "Get-NetLocalGroupMember",
    "Get-NetSession",
    "Get-PathAcl",
    "ConhernetvertFrom-UACValue",
    "Get-PrincipalContext",
    "New-DomainGroup",
    "New-DomainUser",
    "Add-DomainGroupMember",
    "Set-DomainUserPassword",
    "Invoke-Kerberoast",
    "Export-PowerViewCSV",
    "Find-LocalAdminAccess",
    "Find-DomainLocalGroupMember",
    "Find-DomainShare",
    "Find-DomainUserEvent",
    "Find-DomainProcess",
    "Find-DomainUserLocation",
    "Find-InterestingFile",
    "Find-InterestingDomainShareFile",
    "Find-DomainObjectPropertyOutlier",
    "TestMethod",
    "Get-Domain",
    "Get-NetDomain",
    "Get-DomainComputer",
    "Get-NetComputer",
    "Get-DomainController",
    "Get-NetDomainController",
    "Get-DomainFileServer",
    "Get-NetFileServer",
    "Convert-ADName",
    "Get-DomainObject",
    "Get-ADObject",
    "Get-DomainUser",
    "Get-NetUser",
    "Get-DomainGroup",
    "Get-NetGroup",
    "Get-DomainDFSShare",
    "Get-DFSshare",
    "Get-DomainDNSRecord",
    "Get-DNSRecord",
    "Get-DomainDNSZone",
    "Get-DNSZone",
    "Get-DomainForeignGroupMember",
    "Find-ForeignGroup",
    "Get-DomainForeignUser",
    "Find-ForeignUser",
    "ConvertFrom-SID",
    "Convert-SidToName",
    "Get-DomainGroupMember",
    "Get-NetGroupMember",
    "Get-DomainManagedSecurityGroup",
    "Find-ManagedSecurityGroups",
    "Get-DomainOU",
    "Get-NetOU",
    "Get-DomainSID",
    "Get-Forest",
    "Get-NetForest",
    "Get-ForestTrust",
    "Get-NetForestTrust",
    "Get-DomainTrust",
    "Get-NetDomainTrust",
    "Get-ForestDomain",
    "Get-NetForestDomain",
    "Get-DomainSite",
    "Get-NetSite",
    "Get-DomainSubnet",
    "Get-NetSubnet",
    "Get-DomainTrustMapping",
    "Invoke-MapDomainTrust",
    "Get-ForestGlobalCatalog",
    "Get-NetForestCatalog",
    "Get-DomainUserEvent",
    "Get-UserEvent",
    "Get-DomainGUIDMap",
    "Get-GUIDMap",
    "Resolve-IPAddress",
    "Get-IPAddress",
    "ConvertTo-SID",
    "Invoke-UserImpersonation",
    "Invoke-RevertToSelf",
    "Get-DomainSPNTicket",
    "Request-SPNTicket",
    "Get-NetComputerSiteName",
    "Get-SiteName",
    "Get-DomainGPO",
    "Get-NetGPO",
    "Set-DomainObject",
    "Set-ADObject",
    "Add-RemoteConnection",
    "Remove-RemoteConnection",
    "Get-IniContent",
    "Get-GptTmpl",
    "Get-GroupsXML",
    "Get-DomainPolicyData",
    "Get-DomainPolicy",
    "Get-DomainGPOLocalGroup",
    "Get-NetGPOGroup",*/
}


func GetAutoCompleter() *readline.PrefixCompleter {
    items := make([]readline.PrefixCompleterInterface, len(AutoCompleteCommands))

    for i, cmd := range AutoCompleteCommands {
        if cmd == "bof_execute" {
            items[i] = readline.PcItem(cmd,
		readline.PcItem("enum_whoami"),
                readline.PcItem("enum_localusers"),
                readline.PcItem("enum_domaingroups"),
                readline.PcItem("enum_localgroups"),
                readline.PcItem("enum_domainusers"),
                readline.PcItem("enum_domaingroupmembers"),
                readline.PcItem("enum_arpscan"),
                readline.PcItem("enum_services"),
                readline.PcItem("enum_firewallrules"),
                readline.PcItem("enum_routeprint"),
                readline.PcItem("enum_sessioninfo"),
                readline.PcItem("enum_localsessions"),
                readline.PcItem("enum_schtasks"),
                readline.PcItem("enum_ipconfig"),
                readline.PcItem("enum_netstat"),
                readline.PcItem("enum_adcs"),
                readline.PcItem("priv_unquoted"),
                readline.PcItem("priv_autologon"),
                readline.PcItem("priv_modifiableautorun"),
                readline.PcItem("priv_tokenprivileges"),
                readline.PcItem("priv_alwaysinstallelevated"),


            )
        
	} else if cmd == "pwsploit" {
            items[i] = readline.PcItem(cmd,
			readline.PcItem("recon"),
			readline.PcItem("privesc"),
			readline.PcItem("mimikatz"),
			readline.PcItem("execution"),
			readline.PcItem("persist"),

    		)

	}else if strings.Contains(cmd, "persist"){
	    items[i] = readline.PcItem(cmd,
	    		readline.PcItem("user"),
			readline.PcItem("system"),

	    )

	} else {
            items[i] = readline.PcItem(cmd)
        }
    }

    return readline.NewPrefixCompleter(items...)
}

func ShowHelp() {
    // Command categories
    opsecCommands := []string{
        "screenshot",
	"bof_execute",
        "audio_record",
        "Get-NetLoggedon",
        "Get-NetSession",
        "Get-NetShare",
        "Find-DomainShare",
        "Get-Domain",
        "Get-NetDomain",
        "ConvertFrom-SID",
	"kill",
        // Add other OPSEC-safe commands...
    }

    noOpsecCommands := []string{
        "dump_sam",
        "dump_ekeys",
        "dump_dcsync",
        "dump_logonpasswords",
        "pth",
	"GigiSamDump",
        "sc-spawn",
	"mimikatz_samdump",
        "jump-psexec",
        "execute-assembly",
    }

    // Color definitions
    cyan := "\033[36m"
    red := "\033[31m"
    green := "\033[32m"
    yellow := "\033[33m"
    reset := "\033[0m"

    fmt.Printf("\n%sBayefall Command Help%s\n", green, reset)
    fmt.Println("============================")

    // OPSEC-safe commands
    fmt.Printf("\n%s[ OPSEC-Safe Commands ]%s\n", green, reset)
    for i := 0; i < len(opsecCommands); i += 2 {
        cmd1 := fmt.Sprintf("%-40s", opsecCommands[i])
        cmd2 := ""
        if i+1 < len(opsecCommands) {
            cmd2 = opsecCommands[i+1]
        }
        fmt.Printf("%s%s%s\t%s%s%s\n", green, cmd1, reset, green, cmd2, reset)
    }

    fmt.Println("\n=============================================================================================================================")

    // Non-OPSEC commands
    fmt.Printf("\n%s[ High-Risk Commands ]%s\n", red, reset)
    for i := 0; i < len(noOpsecCommands); i += 2 {
        cmd1 := fmt.Sprintf("%-40s", noOpsecCommands[i])
        cmd2 := ""
        if i+1 < len(noOpsecCommands) {
            cmd2 = noOpsecCommands[i+1]
        }
        fmt.Printf("%s%s%s\t%s%s%s\n", red, cmd1, reset, red, cmd2, reset)
    }

    fmt.Println("\n=============================================================================================================================")

    // SharpView section
    fmt.Printf("\n%s[ SharpView Commands (In-Memory Execution) ]%s\n", yellow, reset)
    fmt.Printf("%sAll SharpView commands:%s\n", yellow, reset)
    fmt.Println(" - Get-* (Domain enumeration)")
    fmt.Println(" - Find-* (Discovery operations)")
    fmt.Println(" - Convert*- (SID/Name translation)")
    fmt.Println(" - Set-* (Modification operations)")

    fmt.Println("\n=============================================================================================================================")

    // Execution notes
    fmt.Printf("\n%sExecution Methods:%s\n", green, reset)
    fmt.Printf("%s[In-Memory]%s: All SharpView commands use execute-assembly\n", cyan, reset)
    fmt.Printf("%s[Direct]%s: Core framework commands\n\n", cyan, reset)
    fmt.Printf("%sWarning:%s Red commands may trigger defensive mechanisms!\n", red, reset)
}
