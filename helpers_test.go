package postauth2fa

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

var (
	testSignKeyBytes       = []byte("0123456789abcdef0123456789abcdef")
	testEncryptionKeyBytes = []byte("abcdef0123456789abcdef0123456789")
)

func newTestModule(t *testing.T) *postauth2fa {
	t.Helper()

	now := time.Now().UTC()
	formTemplate := template.Must(template.New("test").Parse("<html>{{.Username}}|{{.ErrorMessage}}|{{.TOTPCodeLength}}|{{.ChannelSuffix}}</html>"))

	return &postauth2fa{
		SessionInactivityTimeout: time.Hour,
		CookieName:               "cpa_sess",
		CookiePath:               "/",
		UsernamePlaceholder:      "{http.auth.user.id}",
		IPBinding:                "true",
		TOTPCodeLength:           6,
		signKeyBytes:             append([]byte(nil), testSignKeyBytes...),
		encryptionKeyBytes:       append([]byte(nil), testEncryptionKeyBytes...),
		secretsLoadMutex:         &sync.Mutex{},
		formTemplate:             formTemplate,
		logger:                   zap.NewNop(),
		timeNow: func() time.Time {
			return now
		},
	}
}

func testKeyB64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func newRequestWithContext(method, target, username, origURI, clientIP, remoteAddr string, body *http.Request) *http.Request {
	var req *http.Request
	if body != nil {
		req = body
	} else {
		req = httptest.NewRequest(method, target, nil)
	}

	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}

	repl := caddyhttp.NewTestReplacer(req)
	req = caddyhttp.PrepareRequest(req, repl, httptest.NewRecorder(), &caddyhttp.Server{})

	if username != "" {
		repl.Set("http.auth.user.id", username)
	}
	if origURI != "" {
		repl.Set("http.request.orig_uri", origURI)
	}
	if clientIP != "" {
		caddyhttp.SetVar(req.Context(), "client_ip", clientIP)
	} else {
		delete(req.Context().Value(caddyhttp.VarsCtxKey).(map[string]any), "client_ip")
	}

	return req
}

func signedTokenString(t *testing.T, m *postauth2fa, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.signKeyBytes)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func encryptSecretForTest(t *testing.T, plaintext string, key []byte) string {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new gcm: %v", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}

func generateTOTPCodeForTest(t *testing.T, secret string, digits int, now time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}
