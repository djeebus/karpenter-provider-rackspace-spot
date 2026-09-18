/*
Copyright 2026 kanya-approve.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwt builds a token whose exp is offset from now. Only the payload is real;
// nothing here verifies a signature.
func jwt(t *testing.T, offset time.Duration) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{Exp: time.Now().Add(offset).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

// recorder captures the Authorization header of every request that reaches it.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Header.Get("Authorization"))
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
}

func (r *recorder) headers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func newTestTransport(t *testing.T, seed string, mint func(int) string) (*Transport, *recorder, *atomic.Int32) {
	t.Helper()
	rec := &recorder{}
	var calls atomic.Int32
	tr := NewTransport(rec, "https://login.example", "refresh-token", seed)
	tr.refresher = func(context.Context, string, string) (string, error) {
		return mint(int(calls.Add(1))), nil
	}
	return tr, rec, &calls
}

func do(t *testing.T, tr *Transport, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
}

// The bug this package fixes: once the startup token expires the SDK keeps
// sending it, and every call comes back 401. A request made after expiry must
// carry a new token, not the stale one.
func TestRoundTripRefreshesExpiredToken(t *testing.T) {
	stale := jwt(t, -time.Minute)
	fresh := jwt(t, time.Hour)
	tr, rec, calls := newTestTransport(t, stale, func(int) string { return fresh })

	do(t, tr, "https://spot.example/apis/ngpc.rxt.io/v1/serverclasses")

	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 refresh, got %d", got)
	}
	if got, want := rec.headers()[0], "Bearer "+fresh; got != want {
		t.Errorf("request carried the stale token; got %q want %q", got, want)
	}
}

// A token still comfortably in date must be reused. If it were not, every
// request would redeem the refresh token and we would trade an expiry bug for
// a rate-limit one.
func TestRoundTripReusesValidToken(t *testing.T) {
	valid := jwt(t, time.Hour)
	tr, rec, calls := newTestTransport(t, valid, func(int) string { return jwt(t, time.Hour) })

	for range 5 {
		do(t, tr, "https://spot.example/apis/ngpc.rxt.io/v1/serverclasses")
	}

	if got := calls.Load(); got != 0 {
		t.Errorf("expected no refresh for a valid token, got %d", got)
	}
	for i, h := range rec.headers() {
		if want := "Bearer " + valid; h != want {
			t.Errorf("request %d: got %q want %q", i, h, want)
		}
	}
}

// The SDK treats a token as expired 60s before its exp, and so must we --
// otherwise a token that passes our check can still fail validation in flight.
func TestRoundTripRefreshesWithinLeeway(t *testing.T) {
	nearly := jwt(t, 30*time.Second) // inside the 60s leeway
	fresh := jwt(t, time.Hour)
	tr, _, calls := newTestTransport(t, nearly, func(int) string { return fresh })

	do(t, tr, "https://spot.example/apis/ngpc.rxt.io/v1/serverclasses")

	if got := calls.Load(); got != 1 {
		t.Errorf("token inside the leeway window should refresh; got %d refreshes", got)
	}
}

// Injecting a token into the token request would require already having one.
func TestRoundTripSkipsOAuthEndpoint(t *testing.T) {
	tr, rec, calls := newTestTransport(t, jwt(t, -time.Minute), func(int) string {
		t.Error("refreshing while fetching a token would recurse")
		return ""
	})

	do(t, tr, "https://login.example/oauth/token")

	if got := calls.Load(); got != 0 {
		t.Errorf("expected no refresh on the oauth path, got %d", got)
	}
	if h := rec.headers()[0]; h != "" {
		t.Errorf("oauth request should go out unauthenticated, got %q", h)
	}
}

// Karpenter reconciles with large worker counts, so a token expiring under
// load means many goroutines discover it at once. They must produce one
// refresh between them, and -race must stay quiet.
func TestTokenRefreshesOnceUnderConcurrency(t *testing.T) {
	fresh := jwt(t, time.Hour)
	tr, _, calls := newTestTransport(t, jwt(t, -time.Minute), func(n int) string {
		time.Sleep(10 * time.Millisecond) // widen the window for a double refresh
		return fresh
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do(t, tr, "https://spot.example/apis/ngpc.rxt.io/v1/serverclasses")
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("50 concurrent requests should share 1 refresh, got %d", got)
	}
}

// RoundTrip is documented as not mutating the request it is given.
func TestRoundTripDoesNotMutateRequest(t *testing.T) {
	tr, _, _ := newTestTransport(t, jwt(t, time.Hour), func(int) string { return "" })
	req, err := http.NewRequest(http.MethodGet, "https://spot.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if h := req.Header.Get("Authorization"); h != "" {
		t.Errorf("caller's request was mutated: Authorization = %q", h)
	}
}

// A malformed or unparseable token is worth one wasted refresh; sending it
// yields a 401 the SDK reports as a permissions error, which is what sent
// people looking in the wrong place to begin with.
func TestExpiredTreatsUnusableTokensAsExpired(t *testing.T) {
	for name, tok := range map[string]string{
		"empty":          "",
		"not a jwt":      "opaque-token",
		"two segments":   "a.b",
		"bad base64":     "a.!!!.c",
		"payload no exp": base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".s",
	} {
		if !expired(tok) {
			t.Errorf("%s: expected to be treated as expired", name)
		}
	}
	if expired(jwt(t, time.Hour)) {
		t.Error("a valid token was reported expired")
	}
}

// Install must leave the SDK's own transport in the chain -- it carries the
// dialer, timeouts and connection pooling the SDK configured.
func TestInstallPreservesUnderlyingTransport(t *testing.T) {
	rec := &recorder{}
	client := &http.Client{Transport: rec}
	tr := NewTransport(client.Transport, "https://login.example", "rt", jwt(t, time.Hour))
	client.Transport = tr

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if len(rec.headers()) != 1 {
		t.Fatalf("request did not reach the wrapped transport: %d calls", len(rec.headers()))
	}
}

// A refresh that fails must surface as an error rather than sending a request
// with no usable credentials.
func TestRoundTripPropagatesRefreshFailure(t *testing.T) {
	rec := &recorder{}
	tr := NewTransport(rec, "https://login.example", "rt", jwt(t, -time.Minute))
	tr.refresher = func(context.Context, string, string) (string, error) {
		return "", fmt.Errorf("refresh token revoked")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://spot.example/x", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("expected an error when the refresh fails")
	}
	if len(rec.headers()) != 0 {
		t.Error("request should not have been sent without a token")
	}
}
