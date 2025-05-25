package enum

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// OSInfo contains comprehensive system reconnaissance data
type OSInfo struct {
	Hostname           string
	OSDetails          string
	Hardware           string
	UACStatus          string
	Virtualization     string
	UserInfo           string
	UserPrivileges     string
	LoggedOnUsers      string
	NetworkProfile     string
	DNSCache           string
	ARPTable           string
	FirewallProfile    string
	AVProducts         string
	EDRProducts        string
	AppLockerStatus    string
	LSAProtection      string
	CredentialGuard    string
	ProcessTree        string
	CriticalProcesses  string
	Services           string
	InstalledSoftware  string
	Patches            string
	DomainTrusts       string
	SystemDrives       string
	NetworkShares      string
	SystemUptime       string
}

func GetSystemInfo() OSInfo {
	var info OSInfo

	info.Hostname = getHostname()
	info.OSDetails = getOSDetails()
	info.Hardware = getHardwareProfile()
	info.UACStatus = getUACStatus()
	info.Virtualization = getVirtualizationStatus()
	info.UserInfo = getDetailedUserInfo()
	info.UserPrivileges = getUserPrivileges()
	info.LoggedOnUsers = getLoggedOnUsers()
	info.NetworkProfile = getNetworkProfile()
	info.DNSCache = getDNSCache()
	info.ARPTable = getARPTable()
	info.FirewallProfile = getFirewallProfile()
	info.AVProducts = getAVProducts()
	info.EDRProducts = getEDRProducts()
	info.AppLockerStatus = getAppLockerStatus()
	info.LSAProtection = getLSAProtectionStatus()
	info.CredentialGuard = getCredentialGuardStatus()

	return info
}

func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "Unknown"
	}
	return name
}

func getOSDetails() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Unknown"
	}
	defer k.Close()
	prod, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	return fmt.Sprintf("%s (Build %s)", prod, build)
}

func getHardwareProfile() string {
	var cs []struct {
		Manufacturer string
		Model        string
	}
	err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &cs)
	if err != nil || len(cs) == 0 {
		return "Unknown Hardware"
	}
	return fmt.Sprintf("%s %s", cs[0].Manufacturer, cs[0].Model)
}

func getUACStatus() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "UAC Status: Unknown"
	}
	defer k.Close()

	enableLUA, _, _ := k.GetIntegerValue("EnableLUA")
	if enableLUA == 0 {
		return "UAC: Disabled"
	}
	return "UAC: Enabled"
}

func getVirtualizationStatus() string {
	var cs []struct {
		HypervisorPresent bool
	}
	err := wmi.Query("SELECT HypervisorPresent FROM Win32_ComputerSystem", &cs)
	if err == nil && len(cs) > 0 && cs[0].HypervisorPresent {
		return "Virtualization: Hypervisor Detected"
	}

	vmIndicators := []string{
		`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
		`HARDWARE\ACPI\DSDT\VBOX__`,
		`SYSTEM\CurrentControlSet\Services\vm3dmp`,
	}

	for _, path := range vmIndicators {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err == nil {
			k.Close()
			return "Virtualization: Artifacts Detected"
		}
	}

	return "Virtualization: No Indicators Found"
}

func getDetailedUserInfo() string {
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Unknown User"
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "Unknown User"
	}
	sid := user.User.Sid.String()

	if err != nil {
		return "Unknown SID"
	}
	return fmt.Sprintf("%s (SID: %s)", getUsername(), sid)
}

func getUsername() string {
	var size uint32 = 128
	buf := make([]uint16, size)
	err := windows.GetUserNameEx(windows.NameSamCompatible, &buf[0], &size)
	if err != nil {
		return "Unknown"
	}
	return syscall.UTF16ToString(buf)
}

func getUserPrivileges() string {
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Privileges: Unknown"
	}
	defer token.Close()

	var returnLength uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnLength)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "Privileges: Unknown"
	}

	buf := make([]byte, returnLength)
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], returnLength, &returnLength)
	if err != nil {
		return "Privileges: Unknown"
	}

	type LUIDAndAttributes struct {
		Luid       windows.LUID
		Attributes uint32
	}

	type TokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     [1]LUIDAndAttributes
	}

	tp := (*TokenPrivileges)(unsafe.Pointer(&buf[0]))
	count := tp.PrivilegeCount
	privs := (*[1 << 20]LUIDAndAttributes)(unsafe.Pointer(&tp.Privileges[0]))[:count:count]

	var sb strings.Builder
	sb.WriteString("User Privileges:\n")
	for _, p := range privs {
		//name, err := windows.LookupPrivilegeName("", &p.Luid)
		name, err := lookupPrivilegeName(&p.Luid)

		if err != nil {
			name = fmt.Sprintf("LUID: %v", p.Luid)
		}
		state := "Disabled"
		if p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
			state = "Enabled"
		}
		sb.WriteString(fmt.Sprintf("  %-35s [%s]\n", name, state))
	}
	return sb.String()
}

func lookupPrivilegeName(luid *windows.LUID) (string, error) {
    modadvapi32 := syscall.NewLazyDLL("advapi32.dll")
    proc := modadvapi32.NewProc("LookupPrivilegeNameW")
    
    var buf [256]uint16
    bufSize := uint32(len(buf))
    
    ret, _, err := proc.Call(
        0, // lpSystemName (NULL)
        uintptr(unsafe.Pointer(luid)),
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(&bufSize)),
    )
    
    if ret == 0 {
        return "", err
    }
    return windows.UTF16ToString(buf[:bufSize]), nil
}

func getLoggedOnUsers() string {
	var users []struct {
		Name string
	}
	err := wmi.Query("SELECT Name FROM Win32_LoggedOnUser", &users)
	if err != nil {
		return "Logged On Users: Unknown"
	}

	var buf strings.Builder
	buf.WriteString("Logged On Users:\n")
	for _, u := range users {
		buf.WriteString(fmt.Sprintf("  %s\n", u.Name))
	}
	return buf.String()
}

func getNetworkProfile() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "Network Profile: Unknown"
	}

	var buf strings.Builder
	buf.WriteString("Network Interfaces:\n")
	for _, iface := range interfaces {
		buf.WriteString(fmt.Sprintf("  %s\n", iface.Name))
	}
	return buf.String()
}

func getDNSCache() string {
	// Placeholder implementation
	return "DNS Cache: Not Implemented"
}

func getARPTable() string {
	// Placeholder implementation
	return "ARP Table: Not Implemented"
}

func getFirewallProfile() string {
	profiles := []string{"DomainProfile", "StandardProfile", "PublicProfile"}
	var buf strings.Builder

	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`,
		registry.READ,
	)
	if err != nil {
		return "Firewall: Unknown"
	}
	defer k.Close()

	for _, profile := range profiles {
		subk, err := registry.OpenKey(k, profile, registry.READ)
		if err != nil {
			continue
		}
		enable, _, _ := subk.GetIntegerValue("EnableFirewall")
		if enable == 1 {
			buf.WriteString(fmt.Sprintf("%s: Enabled\n", profile))
		} else {
			buf.WriteString(fmt.Sprintf("%s: Disabled\n", profile))
		}
		subk.Close()
	}
	return buf.String()
}

func getAVProducts() string {
	var products []struct {
		DisplayName string
	}
	err := wmi.Query("SELECT displayName FROM AntiVirusProduct", &products)
	if err != nil {
		return "AV Products: Could not retrieve"
	}

	if len(products) == 0 {
		return "AV Products: None detected"
	}

	var sb strings.Builder
	sb.WriteString("AV Products:\n")
	for _, p := range products {
		sb.WriteString(fmt.Sprintf("  %s\n", p.DisplayName))
	}
	return sb.String()
}

func getEDRProducts() string {
	// EDR detection often requires vendor-specific checks or deeper inspection.
	// For now, we'll use common registry keys as heuristics.
	knownEDRs := []string{
		`SOFTWARE\CrowdStrike\Sensor`,
		`SOFTWARE\SentinelOne`,
		`SOFTWARE\Microsoft\Windows Defender Advanced Threat Protection`,
		`SOFTWARE\Cisco\AMP`,
		`SOFTWARE\CarbonBlack`,
	}

	var detected []string
	for _, path := range knownEDRs {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err == nil {
			detected = append(detected, path)
			k.Close()
		}
	}

	if len(detected) == 0 {
		return "EDR Products: None detected"
	}

	return fmt.Sprintf("EDR Products:\n  %s", strings.Join(detected, "\n  "))
}

func getAppLockerStatus() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\SrpV2`,
		registry.READ)
	if err != nil {
		return "AppLocker: Not Configured"
	}
	defer k.Close()

	return "AppLocker: Configured"
}

func getLSAProtectionStatus() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "LSA Protection: Unknown"
	}
	defer k.Close()

	runAsPPL, _, err := k.GetIntegerValue("RunAsPPL")
	if err != nil || runAsPPL == 0 {
		return "LSA Protection: Disabled"
	}
	return "LSA Protection: Enabled"
}

func getCredentialGuardStatus() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "Credential Guard: Unknown"
	}
	defer k.Close()

	status, _, err := k.GetIntegerValue("Enabled")
	if err != nil || status == 0 {
		return "Credential Guard: Disabled"
	}
	return "Credential Guard: Enabled"
}
 

