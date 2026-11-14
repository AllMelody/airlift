package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"log"
	"net/http"
	"os"
	"time"

	"ktkr.us/pkg/airlift/config"
)

const (
	sessionCookie = "s"
	sessionTTL    = 7 * 24 * time.Hour
)

// hmacKey signs session cookies. It is loaded from (or created in) the app
// directory so sessions survive restarts. Sessions are stateless: the cookie
// carries its own expiry, signed with this key.
var hmacKey []byte

func initSessionKey(path string) error {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		hmacKey = b
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return err
	}
	hmacKey = key
	return nil
}

// makeToken returns a signed token that is valid until now+sessionTTL.
func makeToken() string {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().Add(sessionTTL).Unix()))
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(payload)
	return base64.URLEncoding.EncodeToString(mac.Sum(payload))
}

// validToken reports whether v is a well-signed, unexpired session token.
func validToken(v string) bool {
	b, err := base64.URLEncoding.DecodeString(v)
	if err != nil || len(b) != 8+sha256.Size {
		return false
	}
	payload, sum := b[:8], b[8:]
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(payload)
	if !hmac.Equal(sum, mac.Sum(nil)) {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(payload))
	return time.Now().Unix() < exp
}

func loggedIn(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return validToken(c.Value)
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || os.Getenv("AIRLIFT_SECURE_COOKIE") == "1"
}

func signIn(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    makeToken(),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func signOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// configured reports whether an admin password has been set.
func configured() bool { return config.Get().HasPassword() }

// requireLogin guards browser (cookie-authenticated) routes.
func requireLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured() {
			notConfigured(w)
			return
		}
		if loggedIn(r) {
			h(w, r)
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/-/login?return="+r.URL.Path, http.StatusSeeOther)
			return
		}
		http.Error(w, "not logged in", http.StatusForbidden)
	}
}

// requirePassword guards API routes authenticated with the X-Airlift-Password
// header (used by the lift CLI client).
func requirePassword(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured() {
			notConfigured(w)
			return
		}
		pass := r.Header.Get("X-Airlift-Password")
		if pass == "" {
			writeJSON(w, http.StatusForbidden, resp{Err: "password required"})
			return
		}
		if !config.Get().VerifyPass(pass) {
			writeJSON(w, http.StatusForbidden, resp{Err: "incorrect password"})
			return
		}
		h(w, r)
	}
}

func notConfigured(w http.ResponseWriter) {
	log.Print("rejected request: no admin password configured (run: airliftd -setpass)")
	writeJSON(w, http.StatusServiceUnavailable,
		resp{Err: "server has no password configured; run `airliftd -setpass` on the host"})
}
