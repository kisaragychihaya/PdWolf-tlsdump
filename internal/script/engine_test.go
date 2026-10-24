package script

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeScript stores src in a temp file and returns its path.
func writeScript(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.js")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

// newTestEngine builds an engine from src, failing the test on any error.
func newTestEngine(t *testing.T, src string, timeout time.Duration) *Engine {
	t.Helper()
	e, err := NewEngine(writeScript(t, src), timeout)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// newTestRequest builds a request the way an intercepted TLS request looks:
// absolute URL, Host set, some headers attached.
func newTestRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("X-Remove", "1")
	return req
}

func TestNewEngineErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		timeout time.Duration
		want    string
		wantErr error
	}{
		{
			name: "syntax error",
			src:  "var rules = [;",
			want: "compile",
		},
		{
			name: "top-level exception",
			src:  "throw new Error('boom at load');",
			want: "boom at load",
		},
		{
			name: "missing rules",
			src:  "var notRules = [];",
			want: "does not define a `rules` array",
		},
		{
			name: "rules not an array",
			src:  `var rules = { pattern: "x" };`,
			want: "must be an array",
		},
		{
			name: "rule not an object",
			src:  "var rules = [42];",
			want: "rule 0 is not an object",
		},
		{
			name: "missing pattern",
			src:  "var rules = [{ rewriteRequest: function (r) {} }];",
			want: "missing pattern",
		},
		{
			name: "invalid regex",
			src:  `var rules = [{ pattern: "https://([" }];`,
			want: "invalid pattern",
		},
		{
			name: "hook not a function",
			src:  `var rules = [{ pattern: "x", rewriteRequest: 5 }];`,
			want: "rewriteRequest is not a function",
		},
		{
			name:    "load timeout",
			src:     "while (true) {}",
			timeout: 100 * time.Millisecond,
			wantErr: ErrTimeout,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			e, err := NewEngine(writeScript(t, tc.src), timeout)
			if err == nil {
				t.Fatalf("expected an error, got engine with %d rules", len(e.rules))
			}
			if e != nil {
				t.Fatalf("expected nil engine alongside the error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestNewEngineMissingFile(t *testing.T) {
	e, err := NewEngine(filepath.Join(t.TempDir(), "absent.js"), time.Second)
	if err == nil || e != nil {
		t.Fatalf("expected an error for a missing script, got %v, %v", e, err)
	}
}

func TestMatchAndRewriteURL(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "^https://example\\.com/api/",
  rewriteRequest: function (req) {
    req.url = req.url.replace("https://example.com/api/", "https://api.example.com/v2/");
  }
}];`, 2*time.Second)

	orig := newTestRequest(t, "https://example.com/api/users?page=2")
	res, err := e.MatchAndRewrite(orig, nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if !res.Matched || res.Rule != 0 {
		t.Fatalf("matched = %v, rule = %d, want matched rule 0", res.Matched, res.Rule)
	}
	if res.Pattern != "^https://example\\.com/api/" {
		t.Fatalf("pattern = %q", res.Pattern)
	}
	if got := res.Request.URL.String(); got != "https://api.example.com/v2/users?page=2" {
		t.Fatalf("url = %q", got)
	}
	if res.Request.Host != "api.example.com" {
		t.Fatalf("host = %q", res.Request.Host)
	}
	// The caller's request must stay untouched.
	if got := orig.URL.String(); got != "https://example.com/api/users?page=2" {
		t.Fatalf("original url = %q", got)
	}
}

func TestMatchAndRewriteMethodAndHeaders(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    req.method = "post";
    req.headers["X-Added"] = "yes";
    req.headers["Accept"] = ["application/json", "text/html"];
    delete req.headers["X-Remove"];
    req.headers["X-Count"] = 7;
  }
}];`, 2*time.Second)

	orig := newTestRequest(t, "https://example.com/items")
	res, err := e.MatchAndRewrite(orig, nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	req := res.Request
	if req.Method != http.MethodPost {
		t.Fatalf("method = %q, want POST", req.Method)
	}
	if got := req.Header.Get("X-Added"); got != "yes" {
		t.Fatalf("X-Added = %q", got)
	}
	if got := req.Header["Accept"]; len(got) != 2 || got[0] != "application/json" || got[1] != "text/html" {
		t.Fatalf("Accept = %v", got)
	}
	if _, ok := req.Header["X-Remove"]; ok {
		t.Fatalf("X-Remove should have been deleted, header = %v", req.Header)
	}
	if got := req.Header.Get("X-Count"); got != "7" {
		t.Fatalf("X-Count = %q", got)
	}
	if _, ok := orig.Header["X-Remove"]; !ok {
		t.Fatalf("deleting a header must not touch the caller's request: %v", orig.Header)
	}
}

func TestMatchAndRewriteBody(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.body = req.body.replace("secret", "public");
  }
}];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/login"), []byte("token=secret"))
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if got := string(res.Body); got != "token=public" {
		t.Fatalf("body = %q", got)
	}
	req := res.Request
	if req.ContentLength != int64(len("token=public")) {
		t.Fatalf("content length = %d", req.ContentLength)
	}
	if got := req.Header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length header should be re-derived, got %q", got)
	}
	read, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(read) != "token=public" {
		t.Fatalf("request body = %q", read)
	}
}

// A binary body cannot be exposed as text; it round-trips through base64 and
// the script can still replace it.
func TestMatchAndRewriteBinaryBody(t *testing.T) {
	binary := []byte{0xff, 0x00, 0xfe, 0x01}

	t.Run("round trip", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    if (req.bodyEncoding !== "base64") { throw new Error("want base64 encoding, got " + req.bodyEncoding); }
    req.headers["X-Seen"] = "1";
  }
}];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/blob"), binary)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		if string(res.Body) != string(binary) {
			t.Fatalf("body = %v, want %v", res.Body, binary)
		}
	})

	t.Run("script replaces it", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    req.body = "aGk=";
    req.bodyEncoding = "base64";
  }
}];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/blob"), binary)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		if got := string(res.Body); got != "hi" {
			t.Fatalf("body = %q, want %q", got, "hi")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    req.bodyEncoding = "base64";
    req.body = "not base64!!";
  }
}];`, 2*time.Second)
		if _, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/blob"), binary); err == nil {
			t.Fatal("expected an error for an invalid base64 body")
		}
	})
}

func TestMatchAndRewriteHostAndPath(t *testing.T) {
	t.Run("host only", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) { req.host = "staging.example.net"; }
}];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/a/b?c=d"), nil)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		if res.Request.Host != "staging.example.net" || res.Request.URL.Host != "staging.example.net" {
			t.Fatalf("host = %q / url host = %q", res.Request.Host, res.Request.URL.Host)
		}
		if got := res.Request.URL.RequestURI(); got != "/a/b?c=d" {
			t.Fatalf("path = %q", got)
		}
	})

	t.Run("path only", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) { req.path = "/v3/items?limit=5"; }
}];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/a/b?c=d"), nil)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		if res.Request.URL.Host != "example.com" {
			t.Fatalf("host = %q", res.Request.URL.Host)
		}
		if got := res.Request.URL.RequestURI(); got != "/v3/items?limit=5" {
			t.Fatalf("path = %q", got)
		}
		if got := res.Request.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("limit = %q", got)
		}
	})
}

// A request that came off the wire has no scheme; rules must still see an
// absolute URL, with the scheme guessed from the port.
func TestMatchAndRewriteWireRequest(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "^http://example\\.com:80/plain",
  rewriteRequest: function (req) {
    if (req.scheme !== "http") { throw new Error("scheme = " + req.scheme); }
    req.headers["X-Seen"] = req.url;
  }
}];`, 2*time.Second)

	u, err := url.Parse("/plain?x=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req := &http.Request{Method: http.MethodGet, Host: "example.com:80", URL: u, Header: http.Header{}}
	res, err := e.MatchAndRewrite(req, nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected the rule to match a scheme-less request")
	}
	if got := res.Request.Header.Get("X-Seen"); got != "http://example.com:80/plain?x=1" {
		t.Fatalf("X-Seen = %q", got)
	}
}

func TestMatchAndRewriteNoMatch(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "^https://other\\.example/",
  rewriteRequest: function (req) { req.headers["X-Never"] = "1"; }
}];`, 2*time.Second)

	orig := newTestRequest(t, "https://example.com/keep")
	body := []byte("payload")
	res, err := e.MatchAndRewrite(orig, body)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if res.Matched {
		t.Fatal("expected no match")
	}
	if res.Rule != -1 {
		t.Fatalf("rule = %d, want -1", res.Rule)
	}
	if res.Request != orig {
		t.Fatal("unmatched result must return the original request")
	}
	if string(res.Body) != string(body) {
		t.Fatalf("body = %q", res.Body)
	}
	if _, ok := res.Request.Header["X-Never"]; ok {
		t.Fatal("the hook must not run when nothing matches")
	}
}

func TestMatchAndRewriteFirstMatchWins(t *testing.T) {
	e := newTestEngine(t, `
var rules = [
  { pattern: "example\\.com", rewriteRequest: function (req) { req.headers["X-Who"] = "first"; } },
  { pattern: "example\\.com", rewriteRequest: function (req) { req.headers["X-Who"] = "second"; } }
];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if res.Rule != 0 {
		t.Fatalf("rule = %d, want 0", res.Rule)
	}
	if got := res.Request.Header.Get("X-Who"); got != "first" {
		t.Fatalf("X-Who = %q, want first", got)
	}
}

// A rule without a request hook still counts as a match (so its response hook
// can run) and leaves the request alone.
func TestMatchAndRewriteNoRequestHook(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{ pattern: "example\\.com", rewriteResponse: function (resp) { resp.status = 204; } }];`, 2*time.Second)

	orig := newTestRequest(t, "https://example.com/x")
	res, err := e.MatchAndRewrite(orig, []byte("body"))
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected a match")
	}
	if res.Request != orig {
		t.Fatal("without a request hook the original request must be returned")
	}
	if string(res.Body) != "body" {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestMatchAndRewriteReturnedObject(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    return { method: "DELETE", url: req.url + "?deleted=1", headers: req.headers };
  }
}];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/items/7"), nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	if res.Request.Method != http.MethodDelete {
		t.Fatalf("method = %q", res.Request.Method)
	}
	if got := res.Request.URL.RequestURI(); got != "/items/7?deleted=1" {
		t.Fatalf("uri = %q", got)
	}
}

// A JS exception must surface as an error without breaking the engine: the next
// call runs normally.
func TestMatchAndRewriteJSErrorRecovers(t *testing.T) {
	e := newTestEngine(t, `
var calls = 0;
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    calls++;
    if (calls === 1) { throw new Error("boom on first call"); }
    req.headers["X-Calls"] = String(calls);
  }
}];`, 2*time.Second)

	orig := newTestRequest(t, "https://example.com/x")
	res, err := e.MatchAndRewrite(orig, nil)
	if err == nil {
		t.Fatalf("expected an error, got %+v", res)
	}
	if !strings.Contains(err.Error(), "boom on first call") {
		t.Fatalf("error = %q", err)
	}
	if errors.Is(err, ErrTimeout) {
		t.Fatal("a JS exception must not be reported as a timeout")
	}

	res, err = e.MatchAndRewrite(orig, nil)
	if err != nil {
		t.Fatalf("second MatchAndRewrite: %v", err)
	}
	if got := res.Request.Header.Get("X-Calls"); got != "2" {
		t.Fatalf("X-Calls = %q, want 2", got)
	}
}

// An infinite loop in a hook is interrupted and reported as ErrTimeout; the
// runtime must be usable afterwards.
func TestMatchAndRewriteTimeout(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    if (req.headers["X-Hang"]) { while (true) {} }
    req.headers["X-Done"] = "1";
  }
}];`, 150*time.Millisecond)

	hang := newTestRequest(t, "https://example.com/x")
	hang.Header.Set("X-Hang", "yes")

	start := time.Now()
	res, err := e.MatchAndRewrite(hang, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected a timeout, got %+v", res)
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}

	// ClearInterrupt must have run, otherwise this call would abort instantly.
	ok := newTestRequest(t, "https://example.com/x")
	res, err = e.MatchAndRewrite(ok, nil)
	if err != nil {
		t.Fatalf("after timeout: %v", err)
	}
	if got := res.Request.Header.Get("X-Done"); got != "1" {
		t.Fatalf("X-Done = %q", got)
	}
}

func TestRewriteResponse(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) { req.headers["X-Req"] = "1"; },
  rewriteResponse: function (resp) {
    resp.status = 201;
    resp.statusText = "Created";
    resp.headers["X-Rewritten"] = "yes";
    resp.headers["Content-Type"] = "application/json";
    resp.body = '{"ok":true}';
  }
}];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	orig := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain"}, "Content-Length": []string{"4"}},
		Body:       io.NopCloser(strings.NewReader("orig")),
	}
	out, body, err := e.RewriteResponse(res, orig, []byte("orig"))
	if err != nil {
		t.Fatalf("RewriteResponse: %v", err)
	}
	if out.StatusCode != 201 || out.Status != "201 Created" {
		t.Fatalf("status = %d %q", out.StatusCode, out.Status)
	}
	if got := out.Header.Get("X-Rewritten"); got != "yes" {
		t.Fatalf("X-Rewritten = %q", got)
	}
	if got := out.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := string(body); got != `{"ok":true}` {
		t.Fatalf("body = %q", got)
	}
	if out.ContentLength != int64(len(`{"ok":true}`)) {
		t.Fatalf("content length = %d", out.ContentLength)
	}
	if got := out.Header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length header should be re-derived, got %q", got)
	}
	read, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(read) != `{"ok":true}` {
		t.Fatalf("response body = %q", read)
	}

	// The caller's response stays intact.
	if orig.StatusCode != 200 || orig.Header.Get("X-Rewritten") != "" {
		t.Fatalf("original response was mutated: %d %v", orig.StatusCode, orig.Header)
	}
}

func TestRewriteResponseSkipped(t *testing.T) {
	orig := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}}
	body := []byte("unchanged")

	t.Run("no response hook", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{ pattern: "example\\.com", rewriteRequest: function (req) {} }];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		out, gotBody, err := e.RewriteResponse(res, orig, body)
		if err != nil {
			t.Fatalf("RewriteResponse: %v", err)
		}
		if out != orig || string(gotBody) != "unchanged" {
			t.Fatalf("expected the arguments back, got %p %q", out, gotBody)
		}
	})

	t.Run("no match", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{ pattern: "other\\.example", rewriteResponse: function (resp) { resp.status = 500; } }];`, 2*time.Second)
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		out, gotBody, err := e.RewriteResponse(res, orig, body)
		if err != nil {
			t.Fatalf("RewriteResponse: %v", err)
		}
		if out != orig || string(gotBody) != "unchanged" {
			t.Fatalf("expected the arguments back, got %p %q", out, gotBody)
		}
	})

	t.Run("nil result", func(t *testing.T) {
		e := newTestEngine(t, `var rules = [];`, 2*time.Second)
		out, gotBody, err := e.RewriteResponse(nil, orig, body)
		if err != nil {
			t.Fatalf("RewriteResponse: %v", err)
		}
		if out != orig || string(gotBody) != "unchanged" {
			t.Fatalf("expected the arguments back, got %p %q", out, gotBody)
		}
	})
}

func TestHasResponseHook(t *testing.T) {
	matched := func(t *testing.T, e *Engine) *RewriteResult {
		t.Helper()
		res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
		if err != nil {
			t.Fatalf("MatchAndRewrite: %v", err)
		}
		return res
	}

	t.Run("with response hook", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{ pattern: "example\\.com", rewriteResponse: function (resp) {} }];`, 2*time.Second)
		if !e.HasResponseHook(matched(t, e)) {
			t.Fatal("HasResponseHook = false, want true")
		}
	})

	t.Run("request hook only", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{ pattern: "example\\.com", rewriteRequest: function (req) {} }];`, 2*time.Second)
		if e.HasResponseHook(matched(t, e)) {
			t.Fatal("HasResponseHook = true, want false")
		}
	})

	t.Run("no match", func(t *testing.T) {
		e := newTestEngine(t, `
var rules = [{ pattern: "other\\.example", rewriteResponse: function (resp) {} }];`, 2*time.Second)
		if e.HasResponseHook(matched(t, e)) {
			t.Fatal("HasResponseHook = true, want false")
		}
	})

	t.Run("nil result or engine", func(t *testing.T) {
		e := newTestEngine(t, `var rules = [];`, 2*time.Second)
		if e.HasResponseHook(nil) {
			t.Fatal("HasResponseHook(nil) = true, want false")
		}
		var nilEngine *Engine
		if nilEngine.HasResponseHook(matched(t, e)) {
			t.Fatal("nil engine HasResponseHook = true, want false")
		}
	})
}

func TestRewriteResponseJSError(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteResponse: function (resp) { throw new Error("response boom"); }
}];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	orig := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}}
	if _, _, err := e.RewriteResponse(res, orig, []byte("x")); err == nil {
		t.Fatal("expected an error from the failing response hook")
	} else if !strings.Contains(err.Error(), "response boom") {
		t.Fatalf("error = %q", err)
	}
}

func TestMatchAndRewriteInvalidScriptInput(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: ".*",
  rewriteRequest: function (req) { req.method = "  "; }
}];`, 2*time.Second)

	if _, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil); err == nil {
		t.Fatal("expected an error for an empty method")
	}
	if _, err := e.MatchAndRewrite(nil, nil); err == nil {
		t.Fatal("expected an error for a nil request")
	}
	var nilEngine *Engine
	if _, err := nilEngine.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil); err == nil {
		t.Fatal("expected an error for a nil engine")
	}
}

// Concurrent callers are serialised by the engine's mutex; the runtime must not
// be corrupted.
func TestMatchAndRewriteConcurrent(t *testing.T) {
	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com/",
  rewriteRequest: function (req) {
    req.headers["X-Seen"] = req.path;
    req.body = req.body + "-done";
  }
}];`, 2*time.Second)

	const goroutines, iterations = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				req := newTestRequest(t, "https://example.com/g")
				res, err := e.MatchAndRewrite(req, []byte("payload"))
				if err != nil {
					errs <- err
					return
				}
				if !res.Matched {
					errs <- errors.New("expected a match")
					return
				}
				if got := string(res.Body); got != "payload-done" {
					errs <- errors.New("unexpected body: " + got)
					return
				}
				if got := res.Request.Header.Get("X-Seen"); got != "/g" {
					errs <- errors.New("unexpected X-Seen: " + got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// The rewritten request has to survive a real round trip: it is written to a
// socket and parsed by a server, which catches framing mistakes (duplicated
// Content-Length, body length not matching ContentLength) that a structural
// check would miss.
func TestRewrittenRequestIsForwardable(t *testing.T) {
	type received struct {
		method, uri, body string
		header            http.Header
	}
	got := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server read body: %v", err)
		}
		got <- received{method: r.Method, uri: r.URL.RequestURI(), body: string(body), header: r.Header.Clone()}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteRequest: function (req) {
    req.method = "PUT";
    req.path = "/forwarded?via=script";
    req.headers["X-Added"] = "1";
    req.body = req.body + "&extra=1";
  }
}];`, 2*time.Second)

	res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/orig"), []byte("a=b"))
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// What a front-end does before writing: point the request at the upstream.
	out := res.Request.Clone(res.Request.Context())
	out.URL.Scheme = "http"
	out.URL.Host = srv.Listener.Addr().String()
	out.Host = srv.Listener.Addr().String()
	if err := out.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), out)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	select {
	case r := <-got:
		if r.method != http.MethodPut {
			t.Errorf("method = %q, want PUT", r.method)
		}
		if r.uri != "/forwarded?via=script" {
			t.Errorf("uri = %q", r.uri)
		}
		if r.body != "a=b&extra=1" {
			t.Errorf("body = %q", r.body)
		}
		if v := r.header.Get("X-Added"); v != "1" {
			t.Errorf("X-Added = %q", v)
		}
		if v := r.header.Values("Content-Length"); len(v) != 1 {
			t.Errorf("Content-Length sent %d times: %v", len(v), v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never received the rewritten request")
	}
}

// Changing only the status code must not keep the old reason phrase; a custom
// phrase from the script still wins.
func TestRewriteResponseStatusLine(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "status only",
			script: `resp.status = 201;`,
			want:   "201 Created",
		},
		{
			name:   "explicit statusText",
			script: `resp.status = 418; resp.statusText = "Short and stout";`,
			want:   "418 Short and stout",
		},
		{
			name:   "untouched",
			script: `resp.headers["X-Noop"] = "1";`,
			want:   "200 OK",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, `
var rules = [{
  pattern: "example\\.com",
  rewriteResponse: function (resp) { `+tc.script+` }
}];`, 2*time.Second)
			res, err := e.MatchAndRewrite(newTestRequest(t, "https://example.com/x"), nil)
			if err != nil {
				t.Fatalf("MatchAndRewrite: %v", err)
			}
			orig := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}}
			out, _, err := e.RewriteResponse(res, orig, []byte("x"))
			if err != nil {
				t.Fatalf("RewriteResponse: %v", err)
			}
			if out.Status != tc.want {
				t.Fatalf("status line = %q, want %q", out.Status, tc.want)
			}
		})
	}
}
