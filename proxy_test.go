package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestHandler wires a handler over the given clients, all pointing at the
// echo server.
func newTestHandler(t *testing.T, selector Selector, names ...string) *ForwardHandler {
	t.Helper()

	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()

	cfg := &Config{Target: hostOf(server), Selector: selector}
	for _, name := range names {
		certPath, keyPath := ca.issueClient(t, dir, name, time.Now().Add(time.Hour))
		cfg.Clients = append(cfg.Clients, Client{Name: name, Cert: certPath, Key: keyPath})
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	registry, err := NewRegistry(cfg, nil, defaultReloadInterval)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}

	return NewForwardHandler(registry, cfg.Selector)
}

// do issues a request through the handler and returns the response.
func do(handler http.Handler, headers map[string]string) *http.Response {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/some/path", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func TestSelectsCertificateByHeader(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha", "beta")

	for _, name := range []string{"alpha", "beta"} {
		resp := do(handler, map[string]string{"X-Client-Name": name})
		if got := resp.Header.Get("X-Presented-CN"); got != name {
			t.Errorf("selected %q, upstream saw certificate %q", name, got)
		}
	}
}

// TestIdentitiesDoNotShareConnections guards the central correctness property:
// every identity must own its transport. A shared connection pool would let a
// connection opened for one identity serve a request for another, which only
// shows up once connections are actually being reused.
func TestIdentitiesDoNotShareConnections(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha", "beta", "gamma")

	names := []string{"alpha", "beta", "gamma"}
	for round := 0; round < 10; round++ {
		for _, name := range names {
			resp := do(handler, map[string]string{"X-Client-Name": name})
			if got := resp.Header.Get("X-Presented-CN"); got != name {
				t.Fatalf("round %d: requested %q but upstream saw %q (connection reused across identities)", round, name, got)
			}
		}
	}
}

func TestSelectionIsCaseInsensitive(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "ALPHA"})
	if got := resp.Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("expected case-insensitive match to alpha, upstream saw %q", got)
	}
}

func TestSelectionTrimsWhitespace(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "  alpha  "})
	if got := resp.Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("expected whitespace to be trimmed, upstream saw %q", got)
	}
}

func TestUnknownClientIsRejectedWithAvailableNames(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha", "beta")

	resp := do(handler, map[string]string{"X-Client-Name": "delta"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	body := readBody(t, resp)
	for _, want := range []string{"delta", "alpha", "beta"} {
		if !strings.Contains(body, want) {
			t.Errorf("error message %q does not mention %q", body, want)
		}
	}
}

func TestMissingHeaderWithoutDefaultIsRejected(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if body := readBody(t, resp); !strings.Contains(body, "X-Client-Name") {
		t.Errorf("error message %q does not name the expected header", body)
	}
}

func TestMissingHeaderUsesConfiguredDefault(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name", Default: "beta"}, "alpha", "beta")

	resp := do(handler, nil)
	if got := resp.Header.Get("X-Presented-CN"); got != "beta" {
		t.Errorf("expected default beta, upstream saw %q", got)
	}
}

func TestSelectorHeaderStrippedByDefault(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "alpha"})
	if seen := resp.Header.Get("X-Selector-Seen"); seen != "" {
		t.Errorf("selector header leaked upstream as %q", seen)
	}
}

func TestSelectorHeaderForwardedWhenPassthrough(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name", Passthrough: true}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "alpha"})
	if seen := resp.Header.Get("X-Selector-Seen"); seen != "alpha" {
		t.Errorf("selector header not forwarded, upstream saw %q", seen)
	}
}

// TestHostHeaderIsRetargeted covers a defect where the inbound Host survived
// the clone, so the upstream was told the proxy's own listen address.
func TestHostHeaderIsRetargeted(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "alpha"})
	host := resp.Header.Get("X-Received-Host")
	if strings.Contains(host, "localhost:8080") {
		t.Errorf("upstream received the proxy's own host %q", host)
	}
	if host == "" {
		t.Error("upstream received an empty Host header")
	}
}

// TestDebugLoggingPreservesBody covers a defect where reading the body in
// order to log it left nothing to return to the caller.
func TestDebugLoggingPreservesBody(t *testing.T) {
	previous := level
	level = logLevelDebug
	t.Cleanup(func() { level = previous })

	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	resp := do(handler, map[string]string{"X-Client-Name": "alpha"})
	if body := readBody(t, resp); body != "cn=alpha" {
		t.Errorf("body = %q, want %q", body, "cn=alpha")
	}
}

func TestNoSelectorUsesFallback(t *testing.T) {
	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()

	certPath, keyPath := ca.issueClient(t, dir, "solo", time.Now().Add(time.Hour))
	fallback, err := newIdentity("", hostOf(server), certPath, keyPath, defaultReloadInterval)
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}

	registry, err := NewRegistry(&Config{Target: hostOf(server)}, fallback, defaultReloadInterval)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}

	handler := NewForwardHandler(registry, Selector{})
	resp := do(handler, nil)
	if got := resp.Header.Get("X-Presented-CN"); got != "solo" {
		t.Errorf("expected fallback certificate solo, upstream saw %q", got)
	}
}

// TestFallbackUsedWhenHeaderAbsent checks that a command line certificate
// still serves requests that select nothing, alongside configured clients.
func TestFallbackUsedWhenHeaderAbsent(t *testing.T) {
	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()

	alphaCert, alphaKey := ca.issueClient(t, dir, "alpha", time.Now().Add(time.Hour))
	soloCert, soloKey := ca.issueClient(t, dir, "solo", time.Now().Add(time.Hour))

	cfg := &Config{
		Target:   hostOf(server),
		Selector: Selector{Header: "X-Client-Name"},
		Clients:  []Client{{Name: "alpha", Cert: alphaCert, Key: alphaKey}},
	}

	fallback, err := newIdentity("", hostOf(server), soloCert, soloKey, defaultReloadInterval)
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}

	registry, err := NewRegistry(cfg, fallback, defaultReloadInterval)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}

	handler := NewForwardHandler(registry, cfg.Selector)

	if got := do(handler, nil).Header.Get("X-Presented-CN"); got != "solo" {
		t.Errorf("absent header should use fallback solo, upstream saw %q", got)
	}
	if got := do(handler, map[string]string{"X-Client-Name": "alpha"}).Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("explicit selection should use alpha, upstream saw %q", got)
	}
}

// TestCertificateReloadedWhenFileChanges covers rotation by an external
// process while the proxy is running.
func TestCertificateReloadedWhenFileChanges(t *testing.T) {
	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()

	certPath, keyPath := ca.issueClient(t, dir, "rotating", time.Now().Add(time.Hour))

	// A zero interval makes every request re-examine the files.
	id, err := newIdentity("rotating", hostOf(server), certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}

	first := id.expiry()

	// Reissue the same identity with a later expiry, mimicking a sync
	// process replacing the files in place.
	later := time.Now().Add(12 * time.Hour).Truncate(time.Second)
	ca.issueClientAt(t, certPath, keyPath, "rotating", later)
	touch(t, certPath, keyPath)

	id.httpClient()

	if second := id.expiry(); !second.After(first) {
		t.Errorf("expiry %s did not advance past %s; certificate was not reloaded", second, first)
	}
}

// TestReloadFailureKeepsPreviousCertificate covers a partially written file
// appearing mid-rotation, which must not take the proxy down.
func TestReloadFailureKeepsPreviousCertificate(t *testing.T) {
	ca := newTestCA(t)
	server := newEchoServer(t, ca)
	dir := t.TempDir()

	certPath, keyPath := ca.issueClient(t, dir, "fragile", time.Now().Add(time.Hour))

	id, err := newIdentity("fragile", hostOf(server), certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}
	before := id.expiry()

	writeFile(t, certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"))
	touch(t, certPath, keyPath)

	if client := id.httpClient(); client == nil {
		t.Fatal("client became nil after a failed reload")
	}
	if after := id.expiry(); !after.Equal(before) {
		t.Errorf("expiry changed from %s to %s despite a failed reload", before, after)
	}
}

// TestInboundCloseIsNotPropagated covers a defect where an inbound
// "Connection: close" survived on the cloned request as Request.Close, which
// the transport writes back out independently of the header map. Forwarding it
// tells the upstream to close and prevents connection reuse.
func TestInboundCloseIsNotPropagated(t *testing.T) {
	handler := newTestHandler(t, Selector{Header: "X-Client-Name"}, "alpha")

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/x", nil)
	req.Header.Set("X-Client-Name", "alpha")
	req.Close = true

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()

	if got := resp.Header.Get("X-Upstream-Close"); got != "false" {
		t.Errorf("upstream saw Close=%s, want false; inbound close leaked through", got)
	}
	if got := resp.Header.Get("X-Presented-CN"); got != "alpha" {
		t.Errorf("upstream saw certificate %q, want alpha", got)
	}
}

// TestSelectorDefaultUsedWithoutHeader covers a configuration that names
// clients but no selector header, where the default must serve every request
// rather than every request being rejected.
func TestSelectorDefaultUsedWithoutHeader(t *testing.T) {
	handler := newTestHandler(t, Selector{Default: "beta"}, "alpha", "beta")

	resp := do(handler, nil)
	if got := resp.Header.Get("X-Presented-CN"); got != "beta" {
		t.Errorf("upstream saw certificate %q, want the default beta", got)
	}

	// With no selector header configured, a stray header must not select.
	resp = do(handler, map[string]string{"X-Client-Name": "alpha"})
	if got := resp.Header.Get("X-Presented-CN"); got != "beta" {
		t.Errorf("upstream saw certificate %q, want the default beta", got)
	}
}

// touch advances the modification time of the given files, so that a reload is
// detected even on filesystems with coarse timestamp resolution.
func touch(t *testing.T, paths ...string) {
	t.Helper()

	future := time.Now().Add(2 * time.Second)
	for _, path := range paths {
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatalf("touch %s: %v", path, err)
		}
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.TrimSpace(string(data))
}
