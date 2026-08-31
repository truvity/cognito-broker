package cognito

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The credentials must travel as HTTP Basic, not as form fields — a
// confidential client's secret in a request body ends up in logs.
func TestExchangeUsesBasicAuthAndClientCredentials(t *testing.T) {
	var gotAuth, gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")

		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	tok, err := Exchange(context.Background(), srv.Client(), srv.URL, "cid", "sec", []string{"dms/read"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if tok.AccessToken != "tok" {
		t.Errorf("access_token = %q, want tok", tok.AccessToken)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:sec"))
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}

	if strings.Contains(gotBody, "sec") {
		t.Errorf("the secret reached the request body: %q", gotBody)
	}

	if !strings.Contains(gotBody, "grant_type=client_credentials") {
		t.Errorf("body = %q, want grant_type=client_credentials", gotBody)
	}

	if !strings.Contains(gotBody, "scope=dms%2Fread") {
		t.Errorf("body = %q, want the scope", gotBody)
	}
}

// Multiple scopes go on the wire space-separated, per OAuth.
func TestExchangeJoinsScopesWithSpaces(t *testing.T) {
	var gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)

		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":1}`))
	}))
	defer srv.Close()

	if _, err := Exchange(context.Background(), srv.Client(), srv.URL, "c", "s", []string{"a/x", "b/y"}); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if !strings.Contains(gotBody, "scope=a%2Fx+b%2Fy") {
		t.Errorf("body = %q, want space-joined scopes", gotBody)
	}
}

// Cognito refuses client_credentials without a resource-server scope, so
// an empty list is a configuration error and not "every scope".
func TestExchangeRefusesEmptyScopes(t *testing.T) {
	_, err := Exchange(context.Background(), nil, "https://example.invalid/oauth2/token", "c", "s", nil)
	if err == nil {
		t.Fatal("want an error for empty scopes, got nil")
	}
}

func TestExchangeRejectsIncompleteCredentials(t *testing.T) {
	_, err := Exchange(context.Background(), nil, "https://example.invalid/oauth2/token", "c", "", []string{"s"})
	if err == nil {
		t.Fatal("want an error when client_secret is missing, got nil")
	}
}

// The upstream error text must survive: invalid_client is what a pool
// answers when the app client has no resource-server scope, which reads
// as a credential fault and is not one.
func TestExchangeSurfacesUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"no scopes"}`))
	}))
	defer srv.Close()

	_, err := Exchange(context.Background(), srv.Client(), srv.URL, "c", "s", []string{"s"})
	if err == nil {
		t.Fatal("want an error on HTTP 400, got nil")
	}

	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error %q does not name invalid_client", err)
	}
}

// A 200 with no token is a broken endpoint, not a success.
func TestExchangeRefusesEmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	_, err := Exchange(context.Background(), srv.Client(), srv.URL, "c", "s", []string{"s"})
	if err == nil {
		t.Fatal("want an error for an empty access_token, got nil")
	}
}
