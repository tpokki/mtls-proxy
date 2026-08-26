package main

import (
	"strings"
	"testing"
	"time"
)

// resetFlags restores the package level flag variables to their declared
// defaults, so that each test starts from the same state.
func resetFlags(t *testing.T) {
	t.Helper()

	previous := struct {
		port                                        int
		listenAddr, target, certificate, privateKey string
		configPath                                  string
		reloadInterval                              time.Duration
		level                                       logLevel
	}{port, listenAddr, target, certificate, privateKey, configPath, reloadInterval, level}

	port, listenAddr, target = 8080, "", ""
	certificate, privateKey = "certificate.crt", "private.key"
	configPath, reloadInterval = "", defaultReloadInterval

	t.Cleanup(func() {
		port, listenAddr, target = previous.port, previous.listenAddr, previous.target
		certificate, privateKey = previous.certificate, previous.privateKey
		configPath, reloadInterval = previous.configPath, previous.reloadInterval
		level = previous.level
	})
}

func TestResolveListenAddrDefaultsToLoopback(t *testing.T) {
	resetFlags(t)

	if got := resolveListenAddr(&Config{}, map[string]bool{}); got != "127.0.0.1:8080" {
		t.Errorf("listen address = %q, want the loopback default", got)
	}
}

func TestResolveListenAddr(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		set        map[string]bool
		port       int
		listenAddr string
		want       string
	}{
		{
			name: "config value is used when no flag is given",
			cfg:  Config{Listen: "0.0.0.0:9000"},
			set:  map[string]bool{},
			port: 8080,
			want: "0.0.0.0:9000",
		},
		{
			name: "explicit port overrides the config, on loopback",
			cfg:  Config{Listen: "0.0.0.0:9000"},
			set:  map[string]bool{"port": true},
			port: 9999,
			want: "127.0.0.1:9999",
		},
		{
			name:       "explicit listen wins over everything",
			cfg:        Config{Listen: "0.0.0.0:9000"},
			set:        map[string]bool{"listen": true, "port": true},
			port:       9999,
			listenAddr: "0.0.0.0:7000",
			want:       "0.0.0.0:7000",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetFlags(t)
			port, listenAddr = tc.port, tc.listenAddr

			if got := resolveListenAddr(&tc.cfg, tc.set); got != tc.want {
				t.Errorf("listen address = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSetupWithoutConfigMatchesLegacyBehaviour checks that the original
// invocation still produces a single certificate proxy with no selection.
func TestSetupWithoutConfigMatchesLegacyBehaviour(t *testing.T) {
	resetFlags(t)

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()
	certPath, keyPath := ca.issueClient(t, dir, "legacy", time.Now().Add(time.Hour))

	certificate, privateKey, target = certPath, keyPath, hostOf(server)
	set := map[string]bool{"certificate": true, "key": true, "target": true}

	handler, addr, err := setup(set)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if addr != "127.0.0.1:8080" {
		t.Errorf("listen address = %q", addr)
	}

	resp := do(handler, nil)
	if got := resp.Header.Get("X-Presented-CN"); got != "legacy" {
		t.Errorf("upstream saw certificate %q, want legacy", got)
	}
}

func TestSetupWithoutTargetFails(t *testing.T) {
	resetFlags(t)

	if _, _, err := setup(map[string]bool{}); err == nil {
		t.Fatal("expected setup to fail without a target")
	}
}

// TestSetupWithConfigIgnoresDefaultCertificateFlags checks that the non-empty
// defaults of -certificate and -key do not create a phantom fallback identity
// when a configuration file is in use.
func TestSetupWithConfigIgnoresDefaultCertificateFlags(t *testing.T) {
	resetFlags(t)

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()
	alphaCert, alphaKey := ca.issueClient(t, dir, "alpha", time.Now().Add(time.Hour))

	configPath = writeConfig(t, `
target: `+hostOf(server)+`
selector:
  header: X-Client-Name
clients:
  - name: alpha
    cert: `+alphaCert+`
    key: `+alphaKey+`
`)

	// certificate and privateKey keep their defaults, which do not exist on
	// disk. Loading them would fail, so reaching this point proves they were
	// not consulted.
	handler, _, err := setup(map[string]bool{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := do(handler, map[string]string{"X-Client-Name": "alpha"}).Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("upstream saw certificate %q, want alpha", got)
	}

	// Without the header and without a default, the request is rejected
	// rather than falling back to the command line certificate.
	if status := do(handler, nil).StatusCode; status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

// TestSetupWithConfigAndExplicitCertificateAddsFallback checks the combined
// invocation, where a command line certificate serves unselected requests.
func TestSetupWithConfigAndExplicitCertificateAddsFallback(t *testing.T) {
	resetFlags(t)

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()
	alphaCert, alphaKey := ca.issueClient(t, dir, "alpha", time.Now().Add(time.Hour))
	soloCert, soloKey := ca.issueClient(t, dir, "solo", time.Now().Add(time.Hour))

	configPath = writeConfig(t, `
target: `+hostOf(server)+`
selector:
  header: X-Client-Name
clients:
  - name: alpha
    cert: `+alphaCert+`
    key: `+alphaKey+`
`)
	certificate, privateKey = soloCert, soloKey

	handler, _, err := setup(map[string]bool{"certificate": true, "key": true})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := do(handler, nil).Header.Get("X-Presented-CN"); got != "solo" {
		t.Errorf("unselected request used %q, want the command line certificate solo", got)
	}
	if got := do(handler, map[string]string{"X-Client-Name": "alpha"}).Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("selected request used %q, want alpha", got)
	}
}

// TestSetupRejectsUnselectableClients covers a configuration listing clients
// with no way to choose between them, which would otherwise start cleanly and
// reject every request.
func TestSetupRejectsUnselectableClients(t *testing.T) {
	resetFlags(t)

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()
	alphaCert, alphaKey := ca.issueClient(t, dir, "alpha", time.Now().Add(time.Hour))

	configPath = writeConfig(t, `
target: `+hostOf(server)+`
clients:
  - name: alpha
    cert: `+alphaCert+`
    key: `+alphaKey+`
`)

	_, _, err := setup(map[string]bool{})
	if err == nil {
		t.Fatal("expected setup to reject a config whose clients cannot be selected")
	}
	if !strings.Contains(err.Error(), "selector.header") {
		t.Errorf("error %q does not explain how to fix the configuration", err)
	}
}

// TestSetupWithDefaultButNoHeader covers the single-identity configuration,
// where selector.default names the client used for every request.
func TestSetupWithDefaultButNoHeader(t *testing.T) {
	resetFlags(t)

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()
	alphaCert, alphaKey := ca.issueClient(t, dir, "alpha", time.Now().Add(time.Hour))

	configPath = writeConfig(t, `
target: `+hostOf(server)+`
selector:
  default: alpha
clients:
  - name: alpha
    cert: `+alphaCert+`
    key: `+alphaKey+`
`)

	handler, _, err := setup(map[string]bool{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := do(handler, nil).Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("upstream saw certificate %q, want alpha", got)
	}
}

func TestLogLevelFlag(t *testing.T) {
	tests := []struct {
		value string
		want  logLevel
	}{
		{"true", logLevelInfo},  // bare -verbose, as before log levels existed
		{"false", logLevelNone}, // -verbose=false, as before
		{"", logLevelInfo},
		{"none", logLevelNone},
		{"info", logLevelInfo},
		{"debug", logLevelDebug},
		{"DEBUG", logLevelDebug},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			resetFlags(t)
			level = logLevelInfo

			if err := (logLevelFlag{}).Set(tc.value); err != nil {
				t.Fatalf("Set(%q): %v", tc.value, err)
			}
			if level != tc.want {
				t.Errorf("level = %q, want %q", level, tc.want)
			}
		})
	}
}

func TestLogLevelFlagRejectsUnknownValue(t *testing.T) {
	resetFlags(t)

	if err := (logLevelFlag{}).Set("chatty"); err == nil {
		t.Fatal("expected an unknown log level to be rejected")
	}
}
