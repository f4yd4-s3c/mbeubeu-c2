package run

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
	"strings"

)

var mbTypes = []string{"https", "quic", "http"}

var insecureClient = &http.Client{
        Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                        InsecureSkipVerify: true,
                },
        },
        Timeout: 10 * time.Second,
}

var quicClient = &http.Client{
        Transport: &http3.RoundTripper{
                TLSClientConfig: &tls.Config{
                        InsecureSkipVerify: true,
                        NextProtos:         []string{"h3"},
                },
        },
        Timeout: 10 * time.Second,
}

var httpsClient = &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, 
        },
    },
}


func UploadFile(filename string, url string, token string, userAgent string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a buffer to store multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form file field
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}

	// Copy file content to the part
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	// Close the writer
	writer.Close()

	// Create HTTP request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	// Try sending the request using different protocols
	var resp *http.Response
	var client *http.Client
	for _, proto := range mbTypes {
		switch strings.ToLower(proto) {
		case "https":
			client = httpsClient
		case "http":
			client = insecureClient
		case "quic":
			client = quicClient
		default:
			continue
		}
		resp, err = client.Do(req)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("Response:", string(respBody))
	return nil
}

