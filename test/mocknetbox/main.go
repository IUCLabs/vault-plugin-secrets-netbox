// Command mocknetbox is an in-memory stand-in for the NetBox token API used by
// the e2e tests. It implements just enough of /api/users/tokens/ (create by user,
// lookup by key, patch expires, delete) and /api/users/users/ (lookup by
// username) that the plugin exercises — no NetBox or database required.
//
// Any credential it has issued (or the seed admin, MOCKNETBOX_TOKEN) is accepted
// as auth, so admin-token rotation chains work exactly as the plugin relies on.
// Not for production use.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	tokenPrefix = "nbt_"
	tokensPath  = "/api/users/tokens/"
	usersPath   = "/api/users/users/"
)

type tok struct {
	id           int
	key          string
	plaintext    string
	version      int
	writeEnabled bool
	expires      string
	userID       int
}

func (t *tok) credential() string {
	if t.version == 2 {
		return tokenPrefix + t.key + "." + t.plaintext
	}
	return t.plaintext
}

type store struct {
	mu     sync.Mutex
	seq    int
	tokens map[int]*tok
	valid  map[string]bool
	users  map[string]int
}

func (s *store) handle(w http.ResponseWriter, r *http.Request) {
	cred := strings.TrimPrefix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "Token ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid[cred] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch {
	case r.URL.Path == usersPath && r.Method == http.MethodGet:
		results := []map[string]any{}
		if id, ok := s.users[r.URL.Query().Get("username")]; ok {
			results = append(results, map[string]any{"id": id})
		}
		writeJSON(w, 200, map[string]any{"results": results})

	case r.URL.Path == tokensPath && r.Method == http.MethodPost:
		var in struct {
			User         int    `json:"user"`
			WriteEnabled bool   `json:"write_enabled"`
			Version      int    `json:"version"`
			Expires      string `json:"expires"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.seq++
		t := &tok{id: s.seq, plaintext: fmt.Sprintf("secret%d", s.seq), version: in.Version, writeEnabled: in.WriteEnabled, expires: in.Expires, userID: in.User}
		if t.version == 0 {
			t.version = 2
		}
		if t.version == 2 {
			t.key = fmt.Sprintf("key%d", s.seq)
		}
		s.tokens[t.id] = t
		s.valid[t.credential()] = true
		writeJSON(w, 201, map[string]any{"id": t.id, "key": t.key, "token": t.plaintext, "version": t.version, "write_enabled": t.writeEnabled, "expires": t.expires, "user": map[string]any{"id": t.userID}})

	case r.URL.Path == tokensPath && r.Method == http.MethodGet:
		key := r.URL.Query().Get("key")
		results := []map[string]any{}
		for _, t := range s.tokens {
			if key != "" && t.key == key {
				results = append(results, map[string]any{"id": t.id, "key": t.key, "version": t.version, "user": map[string]any{"id": t.userID}})
			}
		}
		writeJSON(w, 200, map[string]any{"results": results})

	case strings.HasPrefix(r.URL.Path, tokensPath):
		id, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(r.URL.Path, tokensPath), "/"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		t, ok := s.tokens[id]
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
			t.expires = in.Expires
			writeJSON(w, 200, map[string]any{"id": t.id, "expires": t.expires})
		case http.MethodDelete:
			delete(s.tokens, id)
			delete(s.valid, t.credential())
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	addr := os.Getenv("MOCKNETBOX_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	seed := os.Getenv("MOCKNETBOX_TOKEN")
	if seed == "" {
		seed = "nbt_admkey.admsecret"
	}
	adminUser := 1
	s := &store{
		tokens: map[int]*tok{1: {id: 1, key: "admkey", plaintext: "admsecret", version: 2, writeEnabled: true, userID: adminUser}},
		valid:  map[string]bool{seed: true},
		users:  map[string]int{"svc-terraform-ipam": 42, "svc-puppet-facts": 43},
	}
	s.seq = 1
	mux := http.NewServeMux()
	mux.HandleFunc(usersPath, s.handle)
	mux.HandleFunc(tokensPath, s.handle)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("mock netbox token API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux)) //nolint:gosec // test-only mock
}
