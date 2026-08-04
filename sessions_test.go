package postauth2fa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateOrUpdateJWTCookieSetsExpectedCookie(t *testing.T) {
	t.Parallel()

	m := newTestModule(t)
	m.CookieDomain = "example.com"

	rec := httptest.NewRecorder()
	m.createOrUpdateJWTCookie(rec, "alice", "203.0.113.10")

	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != m.CookieName ||
		cookie.Path != m.CookiePath ||
		cookie.Domain != m.CookieDomain ||
		!cookie.HttpOnly ||
		!cookie.Secure ||
		cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie: %+v", cookie)
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (any, error) {
		return m.signKeyBytes, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("parse cookie token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["username"] != "alice" {
		t.Fatalf("username claim = %v, want alice", claims["username"])
	}
	if claims["clientIP"] != "203.0.113.10" {
		t.Fatalf("clientIP claim = %v, want 203.0.113.10", claims["clientIP"])
	}
	if int64(claims["iat"].(float64)) != m.now().Unix() {
		t.Fatalf("iat = %v, want %d", claims["iat"], m.now().Unix())
	}
	if int64(claims["exp"].(float64)) != m.now().Add(m.SessionInactivityTimeout).Unix() {
		t.Fatalf("exp = %v, want %d", claims["exp"], m.now().Add(m.SessionInactivityTimeout).Unix())
	}
}

func TestHasValidJWTCookie(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 2, 15, 4, 5, 0, time.UTC)

	tests := []struct {
		name          string
		username      string
		clientIP      string
		tokenUsername string
		tokenClientIP string
		ipBinding     string
		expOffset     time.Duration
		wantValid     bool
		wantSetCookie bool
	}{
		{
			name:          "accepts valid token",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "alice",
			tokenClientIP: "203.0.113.10",
			ipBinding:     "true",
			expOffset:     45 * time.Minute,
			wantValid:     true,
		},
		{
			name:          "rejects mismatched username",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "bob",
			tokenClientIP: "203.0.113.10",
			ipBinding:     "true",
			expOffset:     45 * time.Minute,
		},
		{
			name:          "rejects mismatched ip when binding enabled",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "alice",
			tokenClientIP: "203.0.113.11",
			ipBinding:     "true",
			expOffset:     45 * time.Minute,
		},
		{
			name:          "accepts mismatched ip when binding disabled",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "alice",
			tokenClientIP: "203.0.113.11",
			ipBinding:     "false",
			expOffset:     45 * time.Minute,
			wantValid:     true,
		},
		{
			name:          "rejects expired token",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "alice",
			tokenClientIP: "203.0.113.10",
			ipBinding:     "true",
			expOffset:     -time.Minute,
		},
		{
			name:          "extends nearly expired session",
			username:      "alice",
			clientIP:      "203.0.113.10",
			tokenUsername: "alice",
			tokenClientIP: "203.0.113.10",
			ipBinding:     "true",
			expOffset:     10 * time.Minute,
			wantValid:     true,
			wantSetCookie: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestModule(t)
			m.timeNow = func() time.Time {
				return now
			}

			req := newRequestWithContext(http.MethodGet, "https://example.com/secure", tt.username, "/secure", tt.clientIP, "198.51.100.30:1234", nil)
			req.AddCookie(&http.Cookie{
				Name: m.CookieName,
				Value: signedTokenString(t, m, jwt.MapClaims{
					"username": tt.tokenUsername,
					"clientIP": tt.tokenClientIP,
					"iat":      now.Add(-5 * time.Minute).Unix(),
					"exp":      now.Add(tt.expOffset).Unix(),
				}),
			})

			rec := httptest.NewRecorder()
			got := m.hasValidJWTCookie(rec, req, tt.username, tt.clientIP, tt.ipBinding)
			if got != tt.wantValid {
				t.Fatalf("hasValidJWTCookie() = %v, want %v", got, tt.wantValid)
			}

			hasSetCookie := rec.Header().Get("Set-Cookie") != ""
			if hasSetCookie != tt.wantSetCookie {
				t.Fatalf("Set-Cookie present = %v, want %v", hasSetCookie, tt.wantSetCookie)
			}
		})
	}
}
