package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// fakeToken is an in-memory NetBox Token.
type fakeToken struct {
	id           int
	key          string
	plaintext    string
	version      int
	writeEnabled bool
	expires      string
	userID       int
}

func (t *fakeToken) credential() string {
	if t.version == 2 {
		return tokenPrefix + t.key + "." + t.plaintext
	}
	return t.plaintext
}

// fakeNetbox is a minimal stand-in for the NetBox token API. Any credential it
// has issued (or the seeded admin credential) is accepted as admin auth, so
// rotation chains work exactly as in production.
type fakeNetbox struct {
	mu         sync.Mutex
	seq        int
	tokens     map[int]*fakeToken
	valid      map[string]bool // credential -> accepted for auth
	users      map[string]int  // username -> id
	patchCount int
}

func newFakeNetbox() *fakeNetbox {
	return &fakeNetbox{
		tokens: map[int]*fakeToken{},
		valid:  map[string]bool{},
		users:  map[string]int{},
	}
}

// seedAdmin registers a v2 admin token and returns its credential string.
func (f *fakeNetbox) seedAdmin(userID int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t := &fakeToken{id: f.seq, key: fmt.Sprintf("admkey%d", f.seq), plaintext: fmt.Sprintf("admsec%d", f.seq), version: 2, writeEnabled: true, userID: userID}
	f.tokens[t.id] = t
	cred := t.credential()
	f.valid[cred] = true
	return cred
}

// seedAdminV1 registers a v1 admin token and returns its bare credential.
func (f *fakeNetbox) seedAdminV1(userID int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t := &fakeToken{id: f.seq, plaintext: fmt.Sprintf("v1adminplaintext%d", f.seq), version: 1, writeEnabled: true, userID: userID}
	f.tokens[t.id] = t
	cred := t.credential()
	f.valid[cred] = true
	return cred
}

func (f *fakeNetbox) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		cred := strings.TrimPrefix(strings.TrimPrefix(auth, "Bearer "), "Token ")
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.valid[cred] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.URL.Path == usersPath && r.Method == http.MethodGet:
			id, ok := f.users[r.URL.Query().Get("username")]
			results := []map[string]interface{}{}
			if ok {
				results = append(results, map[string]interface{}{"id": id})
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"results": results})

		case r.URL.Path == tokensPath && r.Method == http.MethodPost:
			var in struct {
				User         int    `json:"user"`
				WriteEnabled bool   `json:"write_enabled"`
				Version      int    `json:"version"`
				Expires      string `json:"expires"`
				Description  string `json:"description"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.seq++
			tok := &fakeToken{
				id:           f.seq,
				plaintext:    fmt.Sprintf("secret%d", f.seq),
				version:      in.Version,
				writeEnabled: in.WriteEnabled,
				expires:      in.Expires,
				userID:       in.User,
			}
			if tok.version == 0 {
				tok.version = 2
			}
			if tok.version == 2 {
				tok.key = fmt.Sprintf("key%d", f.seq)
			}
			f.tokens[tok.id] = tok
			f.valid[tok.credential()] = true
			writeJSON(w, http.StatusCreated, map[string]interface{}{
				"id": tok.id, "key": tok.key, "token": tok.plaintext,
				"version": tok.version, "write_enabled": tok.writeEnabled,
				"expires": tok.expires, "user": map[string]interface{}{"id": tok.userID},
			})

		case r.URL.Path == tokensPath && r.Method == http.MethodGet:
			// Lookup by key.
			key := r.URL.Query().Get("key")
			results := []map[string]interface{}{}
			for _, tok := range f.tokens {
				if tok.key == key && key != "" {
					results = append(results, map[string]interface{}{
						"id": tok.id, "key": tok.key, "version": tok.version,
						"user": map[string]interface{}{"id": tok.userID},
					})
				}
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"results": results})

		case strings.HasPrefix(r.URL.Path, tokensPath):
			idStr := strings.Trim(strings.TrimPrefix(r.URL.Path, tokensPath), "/")
			id, err := strconv.Atoi(idStr)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			tok, ok := f.tokens[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			switch r.Method {
			case http.MethodPatch:
				var in struct {
					Expires string `json:"expires"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				tok.expires = in.Expires
				f.patchCount++
				writeJSON(w, http.StatusOK, map[string]interface{}{"id": tok.id, "expires": tok.expires})
			case http.MethodDelete:
				delete(f.tokens, id)
				delete(f.valid, tok.credential())
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestBackend(t *testing.T) (*netboxBackend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return b.(*netboxBackend), config.StorageView
}

func req(t *testing.T, b *netboxBackend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("%s %s: %v", op, path, resp.Error())
	}
	return resp
}

func TestLifecycle(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdmin(100)
	fake.users["svc-puppet-facts"] = 42
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)

	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{
		"netbox_url": srv.URL,
		"token":      admin,
	})

	// Role via username resolution; write_enabled defaults to false (read-only).
	req(t, b, s, logical.CreateOperation, "roles/puppet-facts", map[string]interface{}{
		"netbox_username": "svc-puppet-facts",
		"ttl":             "1h",
		"max_ttl":         "8h",
	})

	role := req(t, b, s, logical.ReadOperation, "roles/puppet-facts", nil)
	if id, _ := toInt(role.Data["netbox_user_id"]); id != 42 {
		t.Fatalf("username not resolved to id: got %v", role.Data["netbox_user_id"])
	}
	if role.Data["write_enabled"].(bool) {
		t.Fatal("write_enabled should default to false")
	}

	creds := req(t, b, s, logical.ReadOperation, "creds/puppet-facts", nil)
	if creds.Secret == nil {
		t.Fatal("creds returned no secret")
	}
	if v := creds.Data["version"].(int); v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}
	tok := creds.Data["token"].(string)
	if !strings.HasPrefix(tok, tokenPrefix) {
		t.Errorf("v2 credential = %q, want %s prefix", tok, tokenPrefix)
	}
	if auth := creds.Data["authorization"].(string); auth != "Bearer "+tok {
		t.Errorf("authorization = %q, want Bearer %s", auth, tok)
	}
	if creds.Data["write_enabled"].(bool) {
		t.Error("minted token should be read-only (write_enabled false)")
	}
	// Expiry aligned to the 1h lease.
	exp, err := time.Parse(time.RFC3339, creds.Data["expires"].(string))
	if err != nil {
		t.Fatalf("parsing expires: %v", err)
	}
	if d := time.Until(exp); d < 55*time.Minute || d > 65*time.Minute {
		t.Errorf("expires not aligned to 1h lease: %s away", d)
	}
	tokenID, _ := toInt(creds.Secret.InternalData["token_id"])
	fake.mu.Lock()
	if _, ok := fake.tokens[tokenID]; !ok {
		t.Error("minted token not present in netbox")
	}
	fake.mu.Unlock()

	// Revoke deletes the token from NetBox.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    creds.Secret,
		Storage:   s,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	fake.mu.Lock()
	if _, ok := fake.tokens[tokenID]; ok {
		t.Error("token still present after revoke")
	}
	fake.mu.Unlock()
}

func TestWriteEnabledRole(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdmin(100)
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{"netbox_url": srv.URL, "token": admin})
	req(t, b, s, logical.CreateOperation, "roles/ipam", map[string]interface{}{
		"netbox_user_id": 7,
		"write_enabled":  true,
		"ttl":            "30m",
	})
	creds := req(t, b, s, logical.ReadOperation, "creds/ipam", nil)
	if !creds.Data["write_enabled"].(bool) {
		t.Fatal("expected write_enabled token")
	}
	if got, _ := toInt(creds.Data["netbox_user_id"]); got != 7 {
		t.Fatalf("netbox_user_id = %v, want 7", creds.Data["netbox_user_id"])
	}
}

func TestRenewExtendsExpiry(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdmin(100)
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{"netbox_url": srv.URL, "token": admin})
	req(t, b, s, logical.CreateOperation, "roles/ci", map[string]interface{}{"netbox_user_id": 7, "ttl": "1h", "max_ttl": "8h"})
	creds := req(t, b, s, logical.ReadOperation, "creds/ci", nil)

	before := fake.patchCount
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    creds.Secret,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("renew returned no secret")
	}
	if fake.patchCount != before+1 {
		t.Errorf("renew did not PATCH netbox expires (patchCount %d -> %d)", before, fake.patchCount)
	}
	tokenID, _ := toInt(creds.Secret.InternalData["token_id"])
	fake.mu.Lock()
	exp, perr := time.Parse(time.RFC3339, fake.tokens[tokenID].expires)
	fake.mu.Unlock()
	if perr != nil {
		t.Fatalf("parsing renewed expires: %v", perr)
	}
	if time.Until(exp) <= 0 {
		t.Error("renewed expiry is not in the future")
	}
}

func TestV1Tokens(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdminV1(100)
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{
		"netbox_url":    srv.URL,
		"token":         admin,
		"token_version": 1,
	})
	req(t, b, s, logical.CreateOperation, "roles/legacy", map[string]interface{}{"netbox_user_id": 7, "ttl": "1h"})
	creds := req(t, b, s, logical.ReadOperation, "creds/legacy", nil)
	if v := creds.Data["version"].(int); v != 1 {
		t.Fatalf("version = %d, want 1", v)
	}
	tok := creds.Data["token"].(string)
	if strings.HasPrefix(tok, tokenPrefix) {
		t.Errorf("v1 credential = %q, should not carry the %s prefix", tok, tokenPrefix)
	}
	if auth := creds.Data["authorization"].(string); auth != "Token "+tok {
		t.Errorf("authorization = %q, want Token %s", auth, tok)
	}
}

func TestConfigRotate(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdmin(100) // registered with key so lookup-by-key works
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{"netbox_url": srv.URL, "token": admin})

	fake.mu.Lock()
	oldCount := len(fake.tokens)
	fake.mu.Unlock()

	rot := req(t, b, s, logical.UpdateOperation, "config/rotate", nil)
	if id, _ := toInt(rot.Data["admin_token_id"]); id == 0 {
		t.Fatal("rotate did not report a new admin_token_id")
	}

	// The old admin credential must no longer be accepted; a new one replaces it.
	fake.mu.Lock()
	if fake.valid[admin] {
		t.Error("old admin credential still valid after rotation")
	}
	if len(fake.tokens) != oldCount {
		t.Errorf("token count changed after rotation: %d -> %d", oldCount, len(fake.tokens))
	}
	fake.mu.Unlock()

	// The engine can still mint using the rotated admin token.
	req(t, b, s, logical.CreateOperation, "roles/after", map[string]interface{}{"netbox_user_id": 7, "ttl": "1h"})
	req(t, b, s, logical.ReadOperation, "creds/after", nil)
}

func TestConfigValidation(t *testing.T) {
	b, s := newTestBackend(t)

	// Missing token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"netbox_url": "https://netbox.example.com"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when token is missing")
	}

	// Bad token_version.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"netbox_url": "https://n", "token": "x", "token_version": 3},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for token_version=3")
	}
}

func TestRoleRequiresUser(t *testing.T) {
	fake := newFakeNetbox()
	admin := fake.seedAdmin(100)
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{"netbox_url": srv.URL, "token": admin})
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/x",
		Data:      map[string]interface{}{"ttl": "1h"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for role without a netbox user")
	}
}

// toInt coerces the numeric shapes returned across storage round-trips.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
