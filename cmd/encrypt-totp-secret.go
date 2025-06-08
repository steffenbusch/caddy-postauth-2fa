// Copyright 2025 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// CLI tool that encrypts a TOTP secret for use in the caddy-postauth-2fa plugin.
// It takes a TOTP secret (Base32) and a base64-encoded AES key (32 bytes / 256 bits),
// encrypts the secret using AES-GCM, and outputs the encrypted secret as a base64
// string for use in the "totp_secret_encrypted" field of the secrets JSON file.
//
// Usage:
//
//	encrypt-totp-secret [TOTP_SECRET] [BASE64_KEY]
//
// If arguments are omitted, the tool will prompt for them interactively.
func main() {
	args := os.Args[1:]

	var totpSecret, base64Key string

	if len(args) >= 1 {
		totpSecret = args[0]
	} else {
		totpSecret = prompt("TOTP Secret (Base32): ")
	}

	if len(args) >= 2 {
		base64Key = args[1]
	} else {
		base64Key = prompt("Encryption Key (Base64, 32 bytes / 256 bits): ")
	}

	keyBytes, err := decodeKey(base64Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error with key: %v\n", err)
		os.Exit(1)
	}

	encrypted, err := encrypt(totpSecret, keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during encryption: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Encrypted TOTP secret (Base64):")
	fmt.Println(encrypted)
}

// prompt reads a line from stdin after displaying the given label.
func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

// decodeKey decodes a base64-encoded key and checks that it is exactly 32 bytes (256 bits) long.
func decodeKey(base64Key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, errors.New("invalid Base64 string")
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (256 bits) long, but is %d bytes", len(decoded))
	}
	return decoded, nil
}

// encrypt encrypts the plaintext using AES-GCM with the provided key and returns a base64-encoded ciphertext.
func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
