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
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// postauth2fa is a Caddy HTTP handler module that adds TOTP-based two-factor authentication (2FA)
// after a primary authentication handler (such as basic_auth). It enforces an additional TOTP code
// check for protected routes. The module supports per-user TOTP secrets (plaintext or AES-GCM-encrypted),
// session management via JWT cookies, and optional IP binding for session validation.
// Features:
//   - TOTP 2FA enforcement after primary authentication (e.g., basic_auth, jwtauth, etc.)
//   - Per-user TOTP secrets (plaintext or encrypted), loaded from a JSON file (map of usernames)
//   - Configurable inactivity timeout for 2FA sessions (JWT-based, stateless, cookie storage)
//   - Optional IP binding for session validation (enabled by default, can be disabled or templated)
//   - Customizable session cookie name, path, and domain
//   - Customizable HTML form template for TOTP code entry
//   - Per-user or global TOTP code length (6 or 8 digits)
//   - Secure handling of secrets and keys (Caddy placeholders and file includes supported)
//   - No server-side session state: JWTs are stateless, reloads/restarts do not invalidate sessions
//
// Note: This module does not provide user management, TOTP provisioning, or logout functionality.
// It is intended to be used together with a primary authentication handler.
type postauth2fa struct {
	// SessionInactivityTimeout defines the maximum allowed period of inactivity before
	// a 2FA session expires and requires re-authentication. Default is 60 minutes.
	SessionInactivityTimeout time.Duration `json:"session_inactivity_timeout,omitempty"`

	// SecretsFilePath specifies the path to the JSON file containing TOTP secrets for each user.
	// This file should contain usernames and their corresponding TOTP secrets.
	SecretsFilePath string `json:"secrets_file_path,omitempty"`

	// CookieName defines the name of the cookie used to store the session token for 2FA.
	// Default is `cpa_sess`.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath specifies the path scope of the cookie.
	// This restricts where the cookie is sent on the server. Default is `/`.
	CookiePath string `json:"cookie_path,omitempty"`

	// CookieDomain specifies the domain scope of the cookie.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// UsernamePlaceholder defines the Caddy placeholder used to extract the authenticated username
	// from the request context. This should match the placeholder set by the authentication handler,
	// such as "{http.auth.user.id}" for basic_auth. If not set, defaults to "{http.auth.user.id}".
	UsernamePlaceholder string `json:"username_placeholder,omitempty"`

	// IPBinding controls whether the session is bound to the client IP address.
	// Accepts "true" (default) or "false". Can use Caddy placeholders.
	IPBinding string `json:"ip_binding,omitempty"`

	// Filename of the custom template to use instead of the embedded default template.
	FormTemplateFile string `json:"form_template,omitempty"`

	// TOTPCodeLength defines the expected length of the TOTP code (default: 6).
	TOTPCodeLength int `json:"totp_code_length,omitempty"`

	// template is the parsed HTML template used to render the 2FA form.
	formTemplate *template.Template

	// SignKey is the base64 encoded secret key used to sign the JWTs.
	SignKey string `json:"sign_key,omitempty"`

	// signKeyBytes is the base64 decoded secret key used to sign the JWTs.
	signKeyBytes []byte

	// EncryptionKey is the base64 encoded key used to decrypt encrypted TOTP secrets.
	EncryptionKey string `json:"encryption_key,omitempty"`

	// encryptionKeyBytes is the base64 decoded key used for decryption.
	encryptionKeyBytes []byte

	// loadedUserSecrets holds the map of user secrets and TOTP code lengths, loaded from the SecretsFilePath JSON file.
	// This map is populated when the file is read and accessed when validating TOTP codes.
	loadedUserSecrets map[string]userSecretEntry

	// secretsLoadMutex is used to synchronize access to the loadedUserSecrets map.
	// This prevents race conditions when loading or accessing user secrets.
	secretsLoadMutex *sync.Mutex

	// logger provides structured logging for the module.
	// It's initialized in the Provision method and used throughout the module for debug information.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (postauth2fa) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.postauth2fa",
		New: func() caddy.Module { return new(postauth2fa) },
	}
}

// Provision sets up the module, initializes the logger, and applies default values.
func (m *postauth2fa) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	repl := caddy.NewReplacer()

	// Initialize the mutex if it's nil
	if m.secretsLoadMutex == nil {
		m.secretsLoadMutex = &sync.Mutex{}
	}

	// Set default values if not provided
	if m.CookieName == "" {
		m.CookieName = "cpa_sess"
	}
	if m.CookiePath == "" {
		m.CookiePath = "/"
	}
	if m.SessionInactivityTimeout == 0 {
		m.SessionInactivityTimeout = 60 * time.Minute // Default inactivity timeout
	}
	// Set default TOTP code length if not provided
	if m.TOTPCodeLength == 0 {
		m.TOTPCodeLength = 6
	}

	// Replace placeholders in the SignKey such as {file./path/to/jwt-secret.txt}
	m.SignKey = repl.ReplaceAll(m.SignKey, "")

	var err error
	m.signKeyBytes, err = base64.StdEncoding.DecodeString(m.SignKey)
	if err != nil {
		m.logger.Error("Failed to decode sign key", zap.Error(err))
		return err
	}

	// Replace placeholders in the EncryptionKey such as {env.TOTP_ENCRYPTION_KEY}
	m.EncryptionKey = repl.ReplaceAll(m.EncryptionKey, "")
	m.encryptionKeyBytes, err = base64.StdEncoding.DecodeString(m.EncryptionKey)
	if err != nil {
		m.logger.Error("Failed to decode encryption key", zap.Error(err))
		return err
	}

	if m.UsernamePlaceholder == "" {
		m.UsernamePlaceholder = "{http.auth.user.id}"
	}

	// Set default for IPBinding if not provided
	if m.IPBinding == "" {
		m.IPBinding = "true"
	}

	// Provision the HTML template
	if err = m.provisionTemplate(); err != nil {
		return err
	}

	// Log the chosen configuration values
	m.logger.Info("postauth2fa plugin configured",
		zap.String("Secrets File Path", m.SecretsFilePath),
		zap.String("Username Placeholder", m.UsernamePlaceholder),
		zap.String("Cookie name", m.CookieName),
		zap.String("Cookie path", m.CookiePath),
		zap.String("Cookie domain", m.CookieDomain),
		zap.String("Form Template File", m.FormTemplateFile),
		zap.String("IP Binding", m.IPBinding),
		zap.Duration("Session Inactivity Timeout", m.SessionInactivityTimeout),
		zap.Int("TOTP Code Length", m.TOTPCodeLength),
		// SignKey is omitted from the log output for security reasons.
		// EncryptionKey is also omitted.
	)
	return nil
}

// Validate ensures the configuration is correct.
func (m *postauth2fa) Validate() error {
	if m.SessionInactivityTimeout <= 0 {
		return fmt.Errorf("SessionInactivityTimeout must be a positive duration")
	}

	// Check if the base64 encoded sign key is set
	if m.SignKey == "" {
		return fmt.Errorf("SignKey must be defined")
	}

	// Check if the base64 decoded sign key has an appropriate length
	if len(m.signKeyBytes) < 32 { // 32 bytes is commonly recommended as a minimum for security
		return fmt.Errorf("decoded sign key must be at least 32 bytes long, but it is %d bytes long, check the base64 encoded sign key", len(m.signKeyBytes))
	}

	// Check if the optional base64 decoded encryption key has the correct length
	if m.EncryptionKey != "" && len(m.encryptionKeyBytes) != 32 {
		return fmt.Errorf("decoded encryption key must be 32 bytes (256 bits) long, but is %d bytes", len(m.encryptionKeyBytes))
	}

	// Validate TOTPCodeLength
	// Only allow 6 or 8 digits for TOTP codes
	if !isValidTOTPCodeLength(m.TOTPCodeLength) {
		return fmt.Errorf("TOTPCodeLength must be 6 or 8")
	}

	return nil
}

// ServeHTTP handles incoming HTTP requests and checks for IP changes.
func (m *postauth2fa) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Access the replacer from the request context to retrieve the requests original URI / path placeholders.
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		m.logger.Error("Failed to retrieve caddy.Replacer from request context")
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	username := repl.ReplaceAll(m.UsernamePlaceholder, "")
	if username == "" {
		m.logger.Error("No authenticated user found - possible misconfiguration or missing authentication handler")
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("no authenticated user found"))
	}

	// Retrieve the client IP address from the Caddy context.
	clientIP := getClientIP(r.Context(), r.RemoteAddr)

	// Create logger with common fields
	logger := m.logger.With(
		zap.String("username", username),
		zap.String("client_ip", clientIP),
	)

	// Replace placeholders in IPBinding (allows dynamic config)
	ipBindingValue := repl.ReplaceAll(m.IPBinding, "true")

	// Validate session and check IP consistency (IP binding logic is now in hasValidJWTCookie)
	if m.hasValidJWTCookie(w, r, username, clientIP, ipBindingValue) {
		return next.ServeHTTP(w, r)
	}

	// Initialize FormData with the html escaped username
	formData := formData{
		Username: html.EscapeString(username),
	}

	// Attempt to retrieve the TOTP secret for the user.
	// If an error occurs while fetching the secret (e.g., if no TOTP secret is set for the user),
	// log it and show an error message.
	secret, codeLength, err := m.getSecretForUser(username)
	if err != nil {
		logger.Error("Failed to retrieve the user's TOTP secret", zap.String("Secrets File Path", m.SecretsFilePath), zap.Error(err))
		formData.ErrorMessage = "Invalid TOTP configuration. Please contact support."
		m.show2FAForm(w, formData)
		return nil
	}

	// If codeLength is not set in the user secrets file, use the module's configured TOTP code length.
	if codeLength == 0 {
		codeLength = m.TOTPCodeLength
	}

	// Only allow 6 or 8 digits for per-user code length
	if !isValidTOTPCodeLength(codeLength) {
		logger.Error("Invalid per-user TOTP code length", zap.Int("code_length", codeLength))
		formData.ErrorMessage = "Invalid TOTP configuration. Please contact support."
		m.show2FAForm(w, formData)
		return nil
	}
	formData.TOTPCodeLength = codeLength

	if r.Method != http.MethodPost {
		m.show2FAForm(w, formData)
		return nil
	}

	// Parse TOTP code from POST data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return nil
	}

	totpCode := r.FormValue("totp_code")
	// Check if the TOTP code is missing; if so, log and prompt for 2FA again.
	if totpCode == "" {
		logger.Warn("Missing TOTP code in POST")
		m.show2FAForm(w, formData)
		return nil
	}

	// Validate the TOTP code with the user's secret and code length.
	valid, err := validateTOTPCode(totpCode, secret, codeLength)
	if !valid || err != nil {
		// If validation fails, log an invalid TOTP attempt for monitoring tools like fail2ban.
		logger.Warn("Invalid TOTP attempt", zap.Error(err))
		formData.ErrorMessage = "Invalid TOTP code. Please try again."
		m.show2FAForm(w, formData)
		return nil
	}

	// Create a new JWT session cookie for the user on successful TOTP validation.
	m.createOrUpdateJWTCookie(w, username, clientIP)

	// Retrieve the unmodified request's original URI (e.g., full path before handle_path stripped it).
	// Fallback to the current request URI if the request's original URI is unavailable.
	redirectURL := repl.ReplaceAll("{http.request.orig_uri}", r.URL.RequestURI())

	// Log the final redirect decision for debugging purposes.
	logger.Debug("Session ok, redirecting",
		zap.String("redirect_url", redirectURL),
		zap.String("current_request_uri", r.URL.RequestURI()),
	)

	// Redirect the client to the original requested URL.
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context, remoteAddr string) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	// If the client IP is empty, extract it from the request's RemoteAddr.
	var err error
	clientIP, _, err = net.SplitHostPort(remoteAddr)
	if err != nil {
		// Use the complete RemoteAddr string as a last resort.
		clientIP = remoteAddr
	}
	return clientIP.(string)
}

func isValidTOTPCodeLength(length int) bool {
	return length == int(otp.DigitsSix) || length == int(otp.DigitsEight)
}

func validateTOTPCode(code, secret string, codeLength int) (bool, error) {
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.Digits(codeLength),
		Algorithm: otp.AlgorithmSHA1,
	}
	return totp.ValidateCustom(code, secret, time.Now().UTC(), opts)
}

// Interface guards to ensure postauth2fa implements the necessary interfaces.
var (
	_ caddy.Module                = (*postauth2fa)(nil)
	_ caddy.Provisioner           = (*postauth2fa)(nil)
	_ caddy.Validator             = (*postauth2fa)(nil)
	_ caddyhttp.MiddlewareHandler = (*postauth2fa)(nil)
)
