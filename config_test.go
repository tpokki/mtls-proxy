package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `
listen: 127.0.0.1:9000
target: api.example.com

selector:
  header: X-Client-Name
  default: alpha
  passthrough: true

clients:
  - name: alpha
    cert: /certs/alpha.crt
    key: /certs/alpha.key
  - name: beta
    cert: /certs/beta.crt
    key: /certs/beta.key
    target: other.example.com
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Selector.Header != "X-Client-Name" || cfg.Selector.Default != "alpha" || !cfg.Selector.Passthrough {
		t.Errorf("selector = %+v", cfg.Selector)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(cfg.Clients))
	}
	if got := cfg.targetFor(cfg.Clients[0]); got != "api.example.com" {
		t.Errorf("alpha target = %q, want the global target", got)
	}
	if got := cfg.targetFor(cfg.Clients[1]); got != "other.example.com" {
		t.Errorf("beta target = %q, want its own override", got)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, "targets: api.example.com\n")

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected a misspelled field to be rejected")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "valid",
			cfg: Config{
				Target:  "api.example.com",
				Clients: []Client{{Name: "alpha", Cert: "a.crt", Key: "a.key"}},
			},
		},
		{
			name: "missing name",
			cfg: Config{
				Target:  "api.example.com",
				Clients: []Client{{Cert: "a.crt", Key: "a.key"}},
			},
			wantErr: "name is required",
		},
		{
			name: "duplicate name differing only by case",
			cfg: Config{
				Target: "api.example.com",
				Clients: []Client{
					{Name: "alpha", Cert: "a.crt", Key: "a.key"},
					{Name: "ALPHA", Cert: "b.crt", Key: "b.key"},
				},
			},
			wantErr: "duplicate name",
		},
		{
			name: "missing cert",
			cfg: Config{
				Target:  "api.example.com",
				Clients: []Client{{Name: "alpha", Key: "a.key"}},
			},
			wantErr: "cert is required",
		},
		{
			name: "missing key",
			cfg: Config{
				Target:  "api.example.com",
				Clients: []Client{{Name: "alpha", Cert: "a.crt"}},
			},
			wantErr: "key is required",
		},
		{
			name: "no target anywhere",
			cfg: Config{
				Clients: []Client{{Name: "alpha", Cert: "a.crt", Key: "a.key"}},
			},
			wantErr: "no target set",
		},
		{
			name: "per-client target satisfies missing global target",
			cfg: Config{
				Clients: []Client{{Name: "alpha", Cert: "a.crt", Key: "a.key", Target: "own.example.com"}},
			},
		},
		{
			name: "default names an unknown client",
			cfg: Config{
				Target:   "api.example.com",
				Selector: Selector{Header: "X-Client-Name", Default: "ghost"},
				Clients:  []Client{{Name: "alpha", Cert: "a.crt", Key: "a.key"}},
			},
			wantErr: "does not name a configured client",
		},
		{
			name: "default matches a client case-insensitively",
			cfg: Config{
				Target:   "api.example.com",
				Selector: Selector{Header: "X-Client-Name", Default: "ALPHA"},
				Clients:  []Client{{Name: "alpha", Cert: "a.crt", Key: "a.key"}},
			},
		},
		{
			name: "selector without clients",
			cfg: Config{
				Target:   "api.example.com",
				Selector: Selector{Header: "X-Client-Name"},
			},
			wantErr: "no clients are configured",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateErrorListsAvailableClients(t *testing.T) {
	cfg := Config{
		Target:   "api.example.com",
		Selector: Selector{Header: "X-Client-Name", Default: "ghost"},
		Clients: []Client{
			{Name: "alpha", Cert: "a.crt", Key: "a.key"},
			{Name: "beta", Cert: "b.crt", Key: "b.key"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"alpha", "beta"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
