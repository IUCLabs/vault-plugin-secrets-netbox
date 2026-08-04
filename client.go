package netbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// tokenPrefix is prepended to a v2 token's identification key when forming the
// Authorization header (NetBox's TOKEN_PREFIX). A credential string that starts
// with it is a v2 token; otherwise it is a legacy v1 (bare 40-char) token.
const tokenPrefix = "nbt_"

const (
	tokensPath = "/api/users/tokens/"
	usersPath  = "/api/users/users/"
)

// netboxClient talks to the NetBox REST API authenticated with the seeded admin
// token. NetBox 4.6 issues v2 tokens by default (HMAC-digest; the plaintext is
// returned only at creation), which authenticate as "Bearer nbt_<key>.<token>".
// Legacy v1 tokens authenticate as "Token <plaintext>".
type netboxClient struct {
	baseURL    string
	authHeader string // full Authorization header value for the admin token
	version    int    // token version to request when minting (1 or 2)
	httpClient *http.Client
}

// mintedToken is the subset of a NetBox Token we consume.
type mintedToken struct {
	ID           int    `json:"id"`
	Key          string `json:"key"`
	Token        string `json:"token"` // plaintext, only present at creation
	Version      int    `json:"version"`
	WriteEnabled bool   `json:"write_enabled"`
	Expires      string `json:"expires"`
	User         struct {
		ID int `json:"id"`
	} `json:"user"`
}

// mintRequest describes a token to create.
type mintRequest struct {
	UserID       int
	WriteEnabled bool
	Description  string
	Expires      time.Time // zero means non-expiring
}

func newClient(cfg *netboxConfig) (*netboxClient, error) {
	if cfg == nil {
		return nil, errors.New("netbox client configuration is nil")
	}
	if cfg.NetboxURL == "" {
		return nil, errors.New("netbox_url is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("token (admin) is required")
	}

	timeout := defaultHTTPTimeout
	if cfg.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.RequestTimeoutSeconds) * time.Second
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // opt-in via config
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("ca_cert is not a valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}

	version := cfg.TokenVersion
	if version == 0 {
		version = 2
	}

	return &netboxClient{
		baseURL:    strings.TrimRight(cfg.NetboxURL, "/"),
		authHeader: authHeaderFor(cfg.Token),
		version:    version,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// authHeaderFor returns the full Authorization header value for a NetBox token
// credential, inferring the scheme from the token's version (v2 credentials are
// prefixed nbt_ and use Bearer; v1 use Token), exactly as NetBox does.
func authHeaderFor(credential string) string {
	if strings.HasPrefix(credential, tokenPrefix) {
		return "Bearer " + credential
	}
	return "Token " + credential
}

// credentialFor assembles the usable credential string a client presents for a
// minted token: v2 tokens are "nbt_<key>.<plaintext>"; v1 tokens are the bare
// plaintext.
func credentialFor(t *mintedToken) string {
	if t.Version == 2 {
		return tokenPrefix + t.Key + "." + t.Token
	}
	return t.Token
}

// MintToken creates a NetBox token for the given user and returns it (including
// the one-time plaintext).
func (c *netboxClient) MintToken(ctx context.Context, req mintRequest) (*mintedToken, error) {
	body := map[string]interface{}{
		"user":          req.UserID,
		"write_enabled": req.WriteEnabled,
		"version":       c.version,
	}
	if req.Description != "" {
		body["description"] = req.Description
	}
	if !req.Expires.IsZero() {
		body["expires"] = req.Expires.UTC().Format(time.RFC3339)
	}

	var out mintedToken
	if err := c.do(ctx, http.MethodPost, tokensPath, body, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, errors.New("netbox returned an empty token value")
	}
	return &out, nil
}

// ExtendToken updates a token's expiry (used on lease renewal). NetBox permits
// updating expires on an existing token.
func (c *netboxClient) ExtendToken(ctx context.Context, id int, expires time.Time) error {
	body := map[string]interface{}{
		"expires": expires.UTC().Format(time.RFC3339),
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("%s%d/", tokensPath, id), body, nil)
}

// DeleteToken removes a token by id. A missing token is treated as success.
func (c *netboxClient) DeleteToken(ctx context.Context, id int) error {
	if id == 0 {
		return nil
	}
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("%s%d/", tokensPath, id), nil, nil)
}

// LookupTokenByKey finds a v2 token by its identification key, returning its id
// and owning user id. Used to auto-discover the seeded admin token's ids for
// rotation.
func (c *netboxClient) LookupTokenByKey(ctx context.Context, key string) (id, userID int, err error) {
	var out struct {
		Results []mintedToken `json:"results"`
	}
	q := tokensPath + "?" + url.Values{"key": {key}}.Encode()
	if err := c.do(ctx, http.MethodGet, q, nil, &out); err != nil {
		return 0, 0, err
	}
	if len(out.Results) == 0 {
		return 0, 0, errNotFound
	}
	return out.Results[0].ID, out.Results[0].User.ID, nil
}

// ResolveUserID looks up a NetBox user's id by username.
func (c *netboxClient) ResolveUserID(ctx context.Context, username string) (int, error) {
	var out struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	q := usersPath + "?" + url.Values{"username": {username}}.Encode()
	if err := c.do(ctx, http.MethodGet, q, nil, &out); err != nil {
		return 0, err
	}
	if len(out.Results) == 0 {
		return 0, fmt.Errorf("no netbox user found with username %q", username)
	}
	return out.Results[0].ID, nil
}

// errNotFound flags a 404 (or empty lookup) so callers can treat absence as
// non-fatal.
var errNotFound = errors.New("not found")

func (c *netboxClient) do(ctx context.Context, method, path string, payload, out interface{}) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling netbox %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusNotFound {
		if method == http.MethodDelete {
			return nil
		}
		return errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("netbox %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding netbox response: %w", err)
	}
	return nil
}
