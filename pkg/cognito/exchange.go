// Package cognito performs the OAuth 2.0 client_credentials exchange
// against an AWS Cognito hosted token endpoint.
package cognito

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Token is what the token endpoint returns.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Exchange trades an app client's credentials for an access token.
//
// tokenURL is the pool's HOSTED endpoint, https://{domain}/oauth2/token.
// The cognito-idp API host does NOT serve this grant, and pointing at it
// is the most common way to get an unhelpful error from a correct
// configuration.
func Exchange(
	ctx context.Context,
	httpClient *http.Client,
	tokenURL, clientID, clientSecret string,
	scopes []string,
) (*Token, error) {
	// Cognito refuses client_credentials without a resource-server scope,
	// so an empty list is a configuration error rather than "all scopes".
	if len(scopes) == 0 {
		return nil, fmt.Errorf("cognito: at least one scope is required for client_credentials")
	}

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("cognito: client_id and client_secret are both required")
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {strings.Join(scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic auth, not form fields: a confidential client's secret belongs
	// in the Authorization header, where it does not land in a
	// request-body log line.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(clientID+":"+clientSecret)))

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cognito token endpoint: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}

		_ = json.NewDecoder(resp.Body).Decode(&e)

		// invalid_client is the one worth naming: it is what a pool
		// answers when the app client exists but has no resource-server
		// scope, which reads as a credential problem and is not one.
		return nil, fmt.Errorf("cognito token endpoint: HTTP %d %s %s", resp.StatusCode, e.Error, e.Description)
	}

	var tok Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("cognito token endpoint: %w", err)
	}

	if tok.AccessToken == "" {
		return nil, fmt.Errorf("cognito token endpoint: empty access_token")
	}

	return &tok, nil
}
