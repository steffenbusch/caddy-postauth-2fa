package postauth2fa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetSecretForUserPlaintext(t *testing.T) {
	t.Parallel()

	m := newTestModule(t)
	m.SecretsFilePath = writeSecretsFile(t, `{"alice":{"totp_secret":"JBSWY3DPEHPK3PXP","totp_code_length":8}}`)

	secret, codeLength, err := m.getSecretForUser("alice")
	if err != nil {
		t.Fatalf("getSecretForUser() error = %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret = %q, want %q", secret, "JBSWY3DPEHPK3PXP")
	}
	if codeLength != 8 {
		t.Fatalf("codeLength = %d, want 8", codeLength)
	}
}

func TestGetSecretForUserEncrypted(t *testing.T) {
	t.Parallel()

	m := newTestModule(t)
	encryptedSecret := encryptSecretForTest(t, "JBSWY3DPEHPK3PXP", m.encryptionKeyBytes)
	m.SecretsFilePath = writeSecretsFile(t, `{"alice":{"totp_secret_encrypted":"`+encryptedSecret+`","totp_code_length":6}}`)

	secret, codeLength, err := m.getSecretForUser("alice")
	if err != nil {
		t.Fatalf("getSecretForUser() error = %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret = %q, want %q", secret, "JBSWY3DPEHPK3PXP")
	}
	if codeLength != 6 {
		t.Fatalf("codeLength = %d, want 6", codeLength)
	}
}

func TestGetSecretForUserCachesLoadedSecrets(t *testing.T) {
	t.Parallel()

	m := newTestModule(t)
	path := writeSecretsFile(t, `{"alice":{"totp_secret":"OLDSECRET"}}`)
	m.SecretsFilePath = path

	secret, _, err := m.getSecretForUser("alice")
	if err != nil {
		t.Fatalf("first getSecretForUser() error = %v", err)
	}
	if secret != "OLDSECRET" {
		t.Fatalf("first secret = %q, want %q", secret, "OLDSECRET")
	}

	if err := os.WriteFile(path, []byte(`{"alice":{"totp_secret":"NEWSECRET"}}`), 0o600); err != nil {
		t.Fatalf("rewrite secrets file: %v", err)
	}

	secret, _, err = m.getSecretForUser("alice")
	if err != nil {
		t.Fatalf("second getSecretForUser() error = %v", err)
	}
	if secret != "OLDSECRET" {
		t.Fatalf("second secret = %q, want cached %q", secret, "OLDSECRET")
	}
}

func TestGetSecretForUserErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(*testing.T, *postauth2fa)
		wantErr string
	}{
		{
			name: "missing user",
			setup: func(t *testing.T, m *postauth2fa) {
				m.SecretsFilePath = writeSecretsFile(t, `{"alice":{"totp_secret":"JBSWY3DPEHPK3PXP"}}`)
			},
			wantErr: "no TOTP secret found for user: bob",
		},
		{
			name: "invalid encryption key length",
			setup: func(t *testing.T, m *postauth2fa) {
				encryptedSecret := encryptSecretForTest(t, "JBSWY3DPEHPK3PXP", testEncryptionKeyBytes)
				m.SecretsFilePath = writeSecretsFile(t, `{"alice":{"totp_secret_encrypted":"`+encryptedSecret+`"}}`)
				m.encryptionKeyBytes = []byte("short")
			},
			wantErr: "encryption key is invalid",
		},
		{
			name: "invalid json",
			setup: func(t *testing.T, m *postauth2fa) {
				m.SecretsFilePath = writeSecretsFile(t, `{"alice":`)
			},
			wantErr: "failed to decode secrets file",
		},
		{
			name: "missing secret fields",
			setup: func(t *testing.T, m *postauth2fa) {
				m.SecretsFilePath = writeSecretsFile(t, `{"alice":{}}`)
			},
			wantErr: "no TOTP secret (plain or encrypted) found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestModule(t)
			tt.setup(t, m)

			_, _, err := m.getSecretForUser("bob")
			if tt.name != "missing user" {
				_, _, err = m.getSecretForUser("alice")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("getSecretForUser() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func writeSecretsFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}
	return path
}
