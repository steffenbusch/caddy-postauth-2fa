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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// createOrUpdateJWTCookie generates a new JWT with a specified client IP or updates an existing one, and logs the details.
func (m *postauth2fa) createOrUpdateJWTCookie(w http.ResponseWriter, username, clientIP string) {
	expiration := time.Now().Add(m.SessionInactivityTimeout)
	claims := jwt.MapClaims{
		"username": username,
		"clientIP": clientIP,
		"iat":      time.Now().Unix(),
		"exp":      expiration.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(m.signKeyBytes)
	if err != nil {
		m.logger.Error("Failed to sign JWT", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	m.logger.Debug("Created or updated session",
		zap.String("username", username),
		zap.String("client_ip", clientIP),
		zap.String("token", signedToken),
		zap.Time("expires", expiration),
	)

	cookie := &http.Cookie{
		Name:     m.CookieName,
		Value:    signedToken,
		Path:     m.CookiePath,
		Domain:   m.CookieDomain,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)
}

// hasValidJWTCookie checks if there is a valid JWT and, if enabled, matches client IP.
func (m *postauth2fa) hasValidJWTCookie(w http.ResponseWriter, r *http.Request, username, clientIP, ipBindingValue string) bool {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return false
	}

	// Create logger with common fields
	logger := m.logger.With(
		zap.String("username", username),
		zap.String("client_ip", clientIP),
	)

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.signKeyBytes, nil
	}, jwt.WithValidMethods([]string{"HS256"})) // Enforcing HS256 only
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			// Log JWT expiration as info
			logger.Info("JWT has expired", zap.Error(err))
		} else {
			logger.Error("Failed to parse or validate JWT", zap.Error(err))
		}
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Always check username
		if claims["username"] != username {
			logger.Warn("JWT does not match username",
				zap.String("token_username", fmt.Sprintf("%v", claims["username"])),
			)
			return false
		}
		// Only check client IP if IP binding is enabled
		if ipBindingValue != "false" {
			if claims["clientIP"] != clientIP {
				logger.Warn("JWT does not match client IP",
					zap.String("token_client_ip", fmt.Sprintf("%v", claims["clientIP"])),
				)
				return false
			}
		}
		// Extend session if less than 50% of inactivity timeout remains
		expiration := time.Unix(int64(claims["exp"].(float64)), 0)
		threshold := m.SessionInactivityTimeout / 2
		if time.Until(expiration) < threshold {
			logger.Debug("Extending session", zap.Time("expiration", expiration))
			m.createOrUpdateJWTCookie(w, username, clientIP)
		}
		return true
	}
	return false
}
