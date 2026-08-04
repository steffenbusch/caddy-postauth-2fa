package postauth2fa

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*postauth2fa)
		wantErr string
	}{
		{
			name: "rejects non-positive timeout",
			mutate: func(m *postauth2fa) {
				m.SessionInactivityTimeout = 0
			},
			wantErr: "positive duration",
		},
		{
			name: "rejects missing sign key",
			mutate: func(m *postauth2fa) {
				m.SignKey = ""
			},
			wantErr: "SignKey must be defined",
		},
		{
			name: "rejects short sign key",
			mutate: func(m *postauth2fa) {
				m.signKeyBytes = []byte("too-short")
			},
			wantErr: "at least 32 bytes",
		},
		{
			name: "rejects invalid encryption key length",
			mutate: func(m *postauth2fa) {
				m.EncryptionKey = "configured"
				m.encryptionKeyBytes = []byte("short")
			},
			wantErr: "must be 32 bytes",
		},
		{
			name: "rejects invalid response header prefix",
			mutate: func(m *postauth2fa) {
				m.FormResponseHeaderName = "2FA-Required"
			},
			wantErr: "must start with 'X-'",
		},
		{
			name: "rejects invalid totp code length",
			mutate: func(m *postauth2fa) {
				m.TOTPCodeLength = 7
			},
			wantErr: "must be 6 or 8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &postauth2fa{
				SessionInactivityTimeout: time.Minute,
				SignKey:                  testKeyB64(testSignKeyBytes),
				signKeyBytes:             append([]byte(nil), testSignKeyBytes...),
				TOTPCodeLength:           6,
			}
			tt.mutate(m)

			err := m.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestProvisionSetsDefaultsAndDecodesKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signKeyFile := filepath.Join(dir, "sign-key.txt")
	encryptionKeyFile := filepath.Join(dir, "encryption-key.txt")

	if err := os.WriteFile(signKeyFile, []byte(testKeyB64(testSignKeyBytes)), 0o600); err != nil {
		t.Fatalf("write sign key file: %v", err)
	}
	if err := os.WriteFile(encryptionKeyFile, []byte(testKeyB64(testEncryptionKeyBytes)), 0o600); err != nil {
		t.Fatalf("write encryption key file: %v", err)
	}

	m := &postauth2fa{
		SignKey:       "{file." + signKeyFile + "}",
		EncryptionKey: "{file." + encryptionKeyFile + "}",
	}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if m.CookieName != "cpa_sess" ||
		m.CookiePath != "/" ||
		m.SessionInactivityTimeout != time.Hour ||
		m.TOTPCodeLength != 6 ||
		m.UsernamePlaceholder != "{http.auth.user.id}" ||
		m.IPBinding != "true" {
		t.Fatalf("unexpected defaults after Provision(): %+v", m)
	}
	if m.secretsLoadMutex == nil {
		t.Fatalf("secretsLoadMutex is nil after Provision()")
	}
	if !bytes.Equal(m.signKeyBytes, testSignKeyBytes) {
		t.Fatalf("signKeyBytes = %q, want %q", m.signKeyBytes, testSignKeyBytes)
	}
	if !bytes.Equal(m.encryptionKeyBytes, testEncryptionKeyBytes) {
		t.Fatalf("encryptionKeyBytes = %q, want %q", m.encryptionKeyBytes, testEncryptionKeyBytes)
	}
	if m.formTemplate == nil {
		t.Fatalf("formTemplate is nil after Provision()")
	}
}

func TestProvisionLoadsCustomTemplate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	templateFile := filepath.Join(dir, "custom-2fa.html")
	if err := os.WriteFile(templateFile, []byte(`<html>custom {{.Username}} {{.ChannelSuffix}}</html>`), 0o600); err != nil {
		t.Fatalf("write template file: %v", err)
	}

	m := &postauth2fa{
		SignKey:          testKeyB64(testSignKeyBytes),
		EncryptionKey:    testKeyB64(testEncryptionKeyBytes),
		FormTemplateFile: templateFile,
	}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	var buf bytes.Buffer
	if err := m.formTemplate.Execute(&buf, formData{Username: "alice", ChannelSuffix: "_admin"}); err != nil {
		t.Fatalf("execute custom template: %v", err)
	}
	if got := buf.String(); got != "<html>custom alice _admin</html>" {
		t.Fatalf("custom template output = %q, want %q", got, "<html>custom alice _admin</html>")
	}
}

func TestProvisionErrorsOnInvalidKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		m       *postauth2fa
		wantErr string
	}{
		{
			name: "invalid sign key",
			m: &postauth2fa{
				SignKey:       "%%%not-base64%%%",
				EncryptionKey: testKeyB64(testEncryptionKeyBytes),
			},
			wantErr: "illegal base64 data",
		},
		{
			name: "invalid encryption key",
			m: &postauth2fa{
				SignKey:       testKeyB64(testSignKeyBytes),
				EncryptionKey: "%%%not-base64%%%",
			},
			wantErr: "illegal base64 data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.Provision(caddy.Context{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Provision() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSetsDefaultFormResponseHeaderValue(t *testing.T) {
	t.Parallel()

	m := &postauth2fa{
		SessionInactivityTimeout: time.Minute,
		SignKey:                  testKeyB64(testSignKeyBytes),
		signKeyBytes:             append([]byte(nil), testSignKeyBytes...),
		FormResponseHeaderName:   "X-2FA-Required",
		TOTPCodeLength:           6,
	}

	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if m.FormResponseHeaderValue != "true" {
		t.Fatalf("FormResponseHeaderValue = %q, want %q", m.FormResponseHeaderValue, "true")
	}
}

func TestServeHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		secret     userSecretEntry
		request    func(*testing.T, *postauth2fa) *http.Request
		assertions func(*testing.T, *httptest.ResponseRecorder, error, bool)
	}{
		{
			name:     "passes through valid jwt session",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP"},
			request: func(t *testing.T, m *postauth2fa) *http.Request {
				t.Helper()
				req := newRequestWithContext(http.MethodGet, "https://example.com/secure", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", nil)
				req.AddCookie(&http.Cookie{
					Name: m.CookieName,
					Value: signedTokenString(t, m, jwt.MapClaims{
						"username": "alice",
						"clientIP": "203.0.113.10",
						"iat":      m.now().Add(-5 * time.Minute).Unix(),
						"exp":      m.now().Add(45 * time.Minute).Unix(),
					}),
				})
				return req
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if !nextCalled {
					t.Fatalf("next handler was not called")
				}
			},
		},
		{
			name:     "shows form on get without session",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP"},
			request: func(t *testing.T, _ *postauth2fa) *http.Request {
				t.Helper()
				return newRequestWithContext(http.MethodGet, "https://example.com/secure", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", nil)
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", rec.Code)
				}
				if !strings.Contains(rec.Body.String(), "alice") {
					t.Fatalf("response body = %q, want username", rec.Body.String())
				}
			},
		},
		{
			name:     "re-renders form when totp code missing",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP"},
			request: func(t *testing.T, _ *postauth2fa) *http.Request {
				t.Helper()
				form := url.Values{}
				req := httptest.NewRequest(http.MethodPost, "https://example.com/secure", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return newRequestWithContext(http.MethodPost, "https://example.com/secure", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", req)
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", rec.Code)
				}
			},
		},
		{
			name:     "rejects invalid totp code",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP"},
			request: func(t *testing.T, _ *postauth2fa) *http.Request {
				t.Helper()
				form := url.Values{"totp_code": {"000000"}}
				req := httptest.NewRequest(http.MethodPost, "https://example.com/secure", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return newRequestWithContext(http.MethodPost, "https://example.com/secure", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", req)
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				if !strings.Contains(rec.Body.String(), "Invalid TOTP code. Please try again.") {
					t.Fatalf("response body = %q, want invalid TOTP error", rec.Body.String())
				}
			},
		},
		{
			name:     "accepts valid totp code and redirects",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP"},
			request: func(t *testing.T, m *postauth2fa) *http.Request {
				t.Helper()
				code := generateTOTPCodeForTest(t, "JBSWY3DPEHPK3PXP", 6, m.now().UTC())
				form := url.Values{"totp_code": {code}}
				req := httptest.NewRequest(http.MethodPost, "https://example.com/secure", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return newRequestWithContext(http.MethodPost, "https://example.com/secure", "alice", "/original?foo=bar", "203.0.113.10", "198.51.100.20:1234", req)
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				if rec.Code != http.StatusFound {
					t.Fatalf("status = %d, want 302", rec.Code)
				}
				if location := rec.Header().Get("Location"); location != "/original?foo=bar" {
					t.Fatalf("Location = %q, want %q", location, "/original?foo=bar")
				}
				if rec.Header().Get("Set-Cookie") == "" {
					t.Fatalf("expected Set-Cookie header on successful TOTP validation")
				}
			},
		},
		{
			name:     "shows configuration error for invalid per-user code length",
			username: "alice",
			secret:   userSecretEntry{TOTPSecret: "JBSWY3DPEHPK3PXP", TOTPCodeLength: 7},
			request: func(t *testing.T, _ *postauth2fa) *http.Request {
				t.Helper()
				return newRequestWithContext(http.MethodGet, "https://example.com/secure", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", nil)
			},
			assertions: func(t *testing.T, rec *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if err != nil {
					t.Fatalf("ServeHTTP() error = %v", err)
				}
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				if !strings.Contains(rec.Body.String(), "Invalid TOTP configuration. Please contact support.") {
					t.Fatalf("response body = %q, want configuration error", rec.Body.String())
				}
			},
		},
		{
			name:     "returns handler error when username missing",
			username: "",
			request: func(t *testing.T, _ *postauth2fa) *http.Request {
				t.Helper()
				return newRequestWithContext(http.MethodGet, "https://example.com/secure", "", "/original", "203.0.113.10", "198.51.100.20:1234", nil)
			},
			assertions: func(t *testing.T, _ *httptest.ResponseRecorder, err error, nextCalled bool) {
				t.Helper()
				if nextCalled {
					t.Fatalf("next handler should not have been called")
				}
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) {
					t.Fatalf("ServeHTTP() error = %v, want caddyhttp.HandlerError", err)
				}
				if handlerErr.StatusCode != http.StatusInternalServerError {
					t.Fatalf("status code = %d, want 500", handlerErr.StatusCode)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestModule(t)
			if tt.username != "" {
				m.loadedUserSecrets = map[string]userSecretEntry{
					tt.username: tt.secret,
				}
			}

			req := tt.request(t, m)
			rec := httptest.NewRecorder()
			nextCalled := false
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
				return nil
			})

			err := m.ServeHTTP(rec, req, next)
			tt.assertions(t, rec, err, nextCalled)
		})
	}
}

func TestGetClientIP(t *testing.T) {
	t.Parallel()

	req := newRequestWithContext(http.MethodGet, "https://example.com", "alice", "/original", "203.0.113.10", "198.51.100.20:1234", nil)
	if got := getClientIP(req.Context(), req.RemoteAddr); got != "203.0.113.10" {
		t.Fatalf("getClientIP() = %q, want %q", got, "203.0.113.10")
	}

	req = newRequestWithContext(http.MethodGet, "https://example.com", "alice", "/original", "", "198.51.100.20:1234", nil)
	if got := getClientIP(req.Context(), req.RemoteAddr); got != "198.51.100.20" {
		t.Fatalf("getClientIP() fallback = %q, want %q", got, "198.51.100.20")
	}

	req = newRequestWithContext(http.MethodGet, "https://example.com", "alice", "/original", "", "invalid-remote-addr", nil)
	if got := getClientIP(req.Context(), req.RemoteAddr); got != "invalid-remote-addr" {
		t.Fatalf("getClientIP() last resort = %q, want %q", got, "invalid-remote-addr")
	}
}

func TestValidateTOTPCodeAtTime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	code := generateTOTPCodeForTest(t, "JBSWY3DPEHPK3PXP", 6, now)

	valid, err := validateTOTPCodeAtTime(code, "JBSWY3DPEHPK3PXP", 6, now)
	if err != nil {
		t.Fatalf("validateTOTPCodeAtTime() error = %v", err)
	}
	if !valid {
		t.Fatalf("validateTOTPCodeAtTime() = false, want true")
	}

	valid, err = validateTOTPCodeAtTime(code, "JBSWY3DPEHPK3PXP", 8, now)
	if err == nil && valid {
		t.Fatalf("validateTOTPCodeAtTime() with wrong digits = true, want failure")
	}
}
