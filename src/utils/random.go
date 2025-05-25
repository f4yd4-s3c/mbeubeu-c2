package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateRandomString returns a URL-safe random string of given length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("error generating random string: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// Simple wrapper that panics on error for template usage
func MustGenerateRandomString(length int) string {
	s, err := GenerateRandomString(length)
	if err != nil {
		panic(err)
	}
	return s
}


func GenerateRandomStringtwo(length int) (string, error) {

    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b)[:length], nil
}
