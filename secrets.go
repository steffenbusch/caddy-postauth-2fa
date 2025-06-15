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

package postauth2fa

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// userSecretEntry represents a user's TOTP secret and optional code length.
type userSecretEntry struct {
	TOTPSecret          string `json:"totp_secret,omitempty"`
	TOTPSecretEncrypted string `json:"totp_secret_encrypted,omitempty"`
	TOTPCodeLength      int    `json:"totp_code_length,omitempty"`
}

// getSecretForUser retrieves the TOTP secret and code length for a given username.
func (m *postauth2fa) getSecretForUser(username string) (secret string, codeLength int, err error) {
	m.secretsLoadMutex.Lock()
	defer m.secretsLoadMutex.Unlock()

	// Lazy-load or reload the secrets file if not loaded yet.
	if m.loadedUserSecrets == nil {
		if err := m.loadUserSecrets(); err != nil {
			return "", 0, err
		}
	}

	entry, ok := m.loadedUserSecrets[username]
	if !ok {
		return "", 0, fmt.Errorf("no TOTP secret found for user: %s", username)
	}

	switch {
	case entry.TOTPSecret != "":
		secret = entry.TOTPSecret
	case entry.TOTPSecretEncrypted != "":
		if len(m.encryptionKeyBytes) != 32 {
			return "", 0, fmt.Errorf("encrypted TOTP secret found, but no valid encryption key is configured")
		}
		secret, err = decryptTOTPSecret(entry.TOTPSecretEncrypted, m.encryptionKeyBytes)
		if err != nil {
			return "", 0, fmt.Errorf("failed to decrypt TOTP secret for user %s: %w", username, err)
		}
	default:
		return "", 0, fmt.Errorf("no TOTP secret (plain or encrypted) found for user: %s", username)
	}

	return secret, entry.TOTPCodeLength, nil
}

// loadUserSecrets loads the user secrets from the JSON file into loadedUserSecrets.
func (m *postauth2fa) loadUserSecrets() error {
	file, err := os.Open(m.SecretsFilePath)
	if err != nil {
		return fmt.Errorf("failed to open secrets file: %w", err)
	}
	defer file.Close()

	// The file is a map: username -> userSecretEntry
	var secrets map[string]userSecretEntry
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&secrets); err != nil {
		return fmt.Errorf("failed to decode secrets file: %w", err)
	}

	m.loadedUserSecrets = secrets
	return nil
}

// decryptTOTPSecret decrypts a base64 encoded, AES-GCM encrypted TOTP secret.
func decryptTOTPSecret(ciphertextB64 string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aesgcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aesgcm.NonceSize()]
	ciphertext = ciphertext[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
