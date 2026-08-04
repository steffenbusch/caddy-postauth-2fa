package postauth2fa

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`
postauth_2fa {
	cookie_domain example.com
	cookie_name custom_sess
	cookie_path /secure
	encryption_key enc-key
	form_template /tmp/2fa.html
	form_response_header X-2FA challenge
	ip_binding false
	secrets_file_path /tmp/secrets.json
	session_inactivity_timeout 90m
	sign_key sign-key
	totp_code_length 8
	channel_suffix _admin
	username_placeholder {http.auth.user.id}
}
`)

	var m postauth2fa
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if m.CookieDomain != "example.com" ||
		m.CookieName != "custom_sess" ||
		m.CookiePath != "/secure" ||
		m.EncryptionKey != "enc-key" ||
		m.FormTemplateFile != "/tmp/2fa.html" ||
		m.FormResponseHeaderName != "X-2FA" ||
		m.FormResponseHeaderValue != "challenge" ||
		m.IPBinding != "false" ||
		m.SecretsFilePath != "/tmp/secrets.json" ||
		m.SessionInactivityTimeout != 90*time.Minute ||
		m.SignKey != "sign-key" ||
		m.TOTPCodeLength != 8 ||
		m.ChannelSuffix != "_admin" ||
		m.UsernamePlaceholder != "{http.auth.user.id}" {
		t.Fatalf("unexpected parsed module: %+v", m)
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "unknown subdirective",
			input: `
postauth_2fa {
	unknown value
}
`,
			wantErr: "unknown subdirective",
		},
		{
			name: "invalid duration",
			input: `
postauth_2fa {
	session_inactivity_timeout later
}
`,
			wantErr: "invalid session_inactivity_timeout duration",
		},
		{
			name: "invalid totp code length",
			input: `
postauth_2fa {
	totp_code_length 7
}
`,
			wantErr: "eiher 6 or 8 digits are allowed",
		},
		{
			name: "too many form response header args",
			input: `
postauth_2fa {
	form_response_header X-2FA true extra
}
`,
			wantErr: "at most two arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m postauth2fa
			err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tt.input))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("UnmarshalCaddyfile() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
