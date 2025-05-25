package linuxb

import (
	"fmt"
	"net"
	"sync"
	"sort"
	"time"
)


var commonPorts = map[int]string{
	7:     "echo",
	9:     "discard",
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	37:    "time",
	42:    "nameserver",
	43:    "whois",
	49:    "tacacs",
	53:    "dns",
	67:    "dhcp-server",
	68:    "dhcp-client",
	69:    "tftp",
	70:    "gopher",
	79:    "finger",
	80:    "http",
	88:    "kerberos",
	102:   "microsoft-exchange",
	110:   "pop3",
	113:   "ident",
	119:   "nntp",
	123:   "ntp",
	135:   "msrpc",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	179:   "bgp",
	194:   "irc",
	201:   "appletalk",
	209:   "qmtp",
	218:   "mpp",
	220:   "imap3",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	464:   "kpasswd",
	465:   "smtps",
	500:   "ike",
	514:   "syslog",
	515:   "printer",
	520:   "rip",
	521:   "ripng",
	540:   "uucp",
	543:   "klogin",
	544:   "kshell",
	546:   "dhcpv6-client",
	547:   "dhcpv6-server",
	548:   "afp",
	554:   "rtsp",
	563:   "nntps",
	587:   "smtp-submission",
	591:   "http-alt",
	593:   "microsoft-dcom",
	636:   "ldaps",
	639:   "msdp",
	646:   "ldp",
	647:   "dhcp-failover",
	648:   "rrp",
	652:   "dtcp",
	665:   "sun-dr",
	666:   "doom",
	674:   "acap",
	688:   "realm-rusd",
	691:   "microsoft-exchange-routing",
	694:   "ha-cluster",
	749:   "kerberos-adm",
	853:   "dns-over-tls",
	860:   "iscsi",
	873:   "rsync",
	902:   "vmware-authd",
	989:   "ftps-data",
	990:   "ftps",
	993:   "imaps",
	995:   "pop3s",
	1025:  "microsoft-rpc",
	1026:  "microsoft-rpc",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "ms-sql-s",
	1521:  "oracle-db",
	1723:  "pptp",
	1900:  "upnp",
	2049:  "nfs",
	2082:  "cpanel",
	2083:  "cpanel-ssl",
	2086:  "webhost-manager",
	2087:  "webhost-manager-ssl",
	2095:  "webmail",
	2096:  "webmail-ssl",
	2181:  "zookeeper",
	2375:  "docker",
	2376:  "docker-ssl",
	2424:  "orientdb",
	2483:  "oracle-db-ssl",
	2484:  "oracle-db-ssl",
	2967:  "symantec-av",
	3000:  "nodejs",
	3030:  "couchdb",
	3306:  "mysql",
	3389:  "rdp",
	3690:  "svn",
	4000:  "remoteanything",
	4369:  "epmd",
	4789:  "vxlan",
	4848:  "glassfish",
	4900:  "citrix-ica",
	4993:  "homekit",
	5000:  "upnp",
	5001:  "slingbox",
	5432:  "postgresql",
	5631:  "pcanywhere",
	5985:  "wsman",
	5986:  "wsman-ssl",
	5666:  "nagios",
	5800:  "vnc-http",
	5900:  "vnc",
	5938:  "teamviewer",
	5984:  "couchdb",
	6000:  "x11",
	6379:  "redis",
	6443:  "kubernetes-api",
	6566:  "sane-port",
	6646:  "mysql-proxy",
	6660:  "ircu",
	6667:  "irc",
	6679:  "osaut",
	6697:  "ircs",
	8000:  "http-alt",
	8008:  "http-alt",
	8009:  "ajp",
	8080:  "http-proxy",
	8081:  "blackice",
	8088:  "radan-http",
	8096:  "plex",
	8112:  "privoxy",
	8200:  "sonos",
	8222:  "vmware-authd",
	8443:  "https-alt",
	8500:  "adobe-coldfusion",
	8765:  "golang-pkg",
	8880:  "cddbp-alt",
	8888:  "sun-answerbook",
	9000:  "jenkins",
	9001:  "tor",
	9042:  "cassandra",
	9090:  "websm",
	9100:  "pdl",
	9200:  "elasticsearch",
	9418:  "git",
	9999:  "abyss",
	10000: "webmin",
	11211: "memcached",
	15672: "rabbitmq",
	25565: "minecraft",
	27017: "mongodb",
	28015: "rethinkdb",
	47808: "bacnet",
}

type PortResult struct {
	Port    int
	State   string
	Service string
}



func isPortOpen(host string, port int, timeout time.Duration) bool {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func ScanAllOpenPorts(host string) []PortResult {
    var results []PortResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    concurrency := 100 // number of concurrent scans
    semaphore := make(chan struct{}, concurrency)

    for port := 20; port <= 65000; port++ {
        wg.Add(1)
        semaphore <- struct{}{}
        go func(p int) {
            defer wg.Done()
            defer func() { <-semaphore }()

            if isPortOpen(host, p, 1*time.Second) {
                service, found := commonPorts[p]
                if !found {
                    service = "unknown"
                }
                mu.Lock()
                results = append(results, PortResult{
                    Port:    p,
                    State:   "open",
                    Service: service,
                })
                mu.Unlock()
            }
        }(port)
    }

    wg.Wait()

    // Sort by port number
    sort.Slice(results, func(i, j int) bool {
        return results[i].Port < results[j].Port
    })

    return results
}


func FormatResults(results []PortResult) string {
	output := "PORT     STATE  SERVICE\n"
	for _, res := range results {
		output += fmt.Sprintf("%-8d %-6s %-s\n", res.Port, res.State, res.Service)
	}
	return output
}
