// Package script applies user-supplied JavaScript rules to intercepted HTTP
// traffic.
//
// A script assigns a global `rules` array. Each rule carries a `pattern` (a Go
// regular expression matched against the absolute request URL) and optional
// `rewriteRequest` / `rewriteResponse` hooks. The first rule whose pattern
// matches wins; its hooks are called with plain JavaScript objects mirroring
// the request or response, and may either mutate the object in place or return
// a replacement object.
//
//	var rules = [
//	  {
//	    pattern: "^https://api\\.example\\.com/",
//	    rewriteRequest: function (req) {
//	      req.headers["X-Debug"] = "1";
//	      req.url = req.url.replace("/api/", "/api/v2/");
//	    },
//	    rewriteResponse: function (resp) {
//	      resp.headers["X-Rewritten"] = "yes";
//	    }
//	  }
//	];
//
// The request object exposes method, url, scheme, host, path, headers, body and
// bodyEncoding; the response object exposes status, statusText, headers, body
// and bodyEncoding. Bodies are exposed as text when they are valid UTF-8 and as
// base64 (with bodyEncoding set to "base64") otherwise.
package script

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

// DefaultTimeout bounds every script execution: loading the script at startup
// and each hook invocation at request time.
const DefaultTimeout = 5 * time.Second

// ErrTimeout is returned when a script (the load step or a hook) runs longer
// than the engine timeout. A timed-out script is interrupted; because it may
// have been stopped in the middle of a rule, later calls are not guaranteed to
// observe a consistent JavaScript state.
var ErrTimeout = errors.New("script: execution timed out")

// errInterrupt is the value handed to goja.Runtime.Interrupt. It is never
// compared for identity: ErrTimeout is what callers see.
var errInterrupt = errors.New("script: interrupted")

// Engine owns a goja runtime and the rules compiled from one script file.
//
// A runtime is not safe for concurrent use, so every JavaScript call is
// serialised by mu; concurrent MatchAndRewrite / RewriteResponse calls block
// on each other for the duration of a hook instead of racing. Rules are
// immutable after NewEngine, so matching a URL needs no lock.
type Engine struct {
	path    string
	timeout time.Duration

	mu       sync.Mutex
	vm       *goja.Runtime
	rules    []*compiledRule
	timedOut atomic.Bool
}

// compiledRule is one entry of the script's `rules` array with its regex
// pre-compiled at startup.
type compiledRule struct {
	pattern        *regexp.Regexp
	source         string
	rewriteRequest goja.Callable
	rewriteResp    goja.Callable
}

// RewriteResult is the outcome of MatchAndRewrite. When Matched is false the
// Request and Body fields hold the untouched inputs, so callers can always use
// the result. Rule is -1 when no rule matched.
//
// The same result must be passed to RewriteResponse so the response-side hook
// of the matched rule is the one that runs.
type RewriteResult struct {
	Matched bool
	Rule    int
	Pattern string
	Request *http.Request
	Body    []byte

	rule *compiledRule
}

// NewEngine loads scriptPath and compiles its rules. A timeout of zero or less
// means DefaultTimeout.
//
// Errors are returned for an unreadable file, a script that fails to evaluate
// (syntax error, top-level exception, timeout), a missing or non-array `rules`
// global, a rule without a pattern, and an invalid pattern.
func NewEngine(scriptPath string, timeout time.Duration) (*Engine, error) {
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("script: read %s: %w", scriptPath, err)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	e := &Engine{path: scriptPath, timeout: timeout, vm: goja.New()}

	prog, err := goja.Compile(scriptPath, string(src), false)
	if err != nil {
		return nil, fmt.Errorf("script: compile %s: %w", scriptPath, err)
	}
	e.mu.Lock()
	loadErr := e.withInterrupt(func() error {
		_, err := e.vm.RunProgram(prog)
		return err
	})
	e.mu.Unlock()
	if loadErr != nil {
		return nil, fmt.Errorf("script: load %s: %w", scriptPath, loadErr)
	}
	if err := e.loadRules(); err != nil {
		return nil, err
	}

	slog.Info("script loaded", "path", scriptPath, "rules", len(e.rules), "timeout", timeout)
	return e, nil
}

// loadRules extracts the global `rules` array and pre-compiles each pattern.
func (e *Engine) loadRules() error {
	obj := jsObject(e.vm.GlobalObject().Get("rules"))
	if obj == nil {
		return fmt.Errorf("script: %s does not define a `rules` array", e.path)
	}
	if cls := obj.ClassName(); cls != "Array" {
		return fmt.Errorf("script: %s: `rules` must be an array, got %s", e.path, cls)
	}
	n := int(obj.Get("length").ToInteger())
	rules := make([]*compiledRule, 0, n)
	for i := 0; i < n; i++ {
		item := jsObject(obj.Get(strconv.Itoa(i)))
		if item == nil {
			return fmt.Errorf("script: %s: rule %d is not an object", e.path, i)
		}
		pv := item.Get("pattern")
		if !isSet(pv) {
			return fmt.Errorf("script: %s: rule %d: missing pattern", e.path, i)
		}
		source := pv.String()
		re, err := regexp.Compile(source)
		if err != nil {
			return fmt.Errorf("script: %s: rule %d: invalid pattern %q: %w", e.path, i, source, err)
		}
		rule := &compiledRule{pattern: re, source: source}
		if rule.rewriteRequest, err = ruleHook(item, "rewriteRequest"); err != nil {
			return fmt.Errorf("script: %s: rule %d: %w", e.path, i, err)
		}
		if rule.rewriteResp, err = ruleHook(item, "rewriteResponse"); err != nil {
			return fmt.Errorf("script: %s: rule %d: %w", e.path, i, err)
		}
		rules = append(rules, rule)
	}
	e.rules = rules
	return nil
}

// ruleHook returns the named hook of a rule, or nil when the rule does not
// define it.
func ruleHook(item *goja.Object, name string) (goja.Callable, error) {
	v := item.Get(name)
	if !isSet(v) {
		return nil, nil
	}
	fn, ok := goja.AssertFunction(v)
	if !ok {
		return nil, fmt.Errorf("%s is not a function", name)
	}
	return fn, nil
}

// MatchAndRewrite applies the first rule whose pattern matches req's absolute
// URL. body is the already-read request body; it is handed to the hook and
// returned unchanged when no rule matches or the rule has no rewriteRequest.
//
// The returned request is always a clone when a hook ran, so the caller's
// request (and the recorded headers) are left intact. ContentLength, Body and
// the Content-Length header are re-derived from the (possibly rewritten) body.
// Hooks see and produce in-memory bodies only: streaming is not preserved.
func (e *Engine) MatchAndRewrite(req *http.Request, body []byte) (*RewriteResult, error) {
	if e == nil {
		return nil, errors.New("script: nil engine")
	}
	if req == nil {
		return nil, errors.New("script: nil request")
	}

	target := absoluteURL(req)
	idx := e.match(target)
	if idx < 0 {
		return &RewriteResult{Rule: -1, Request: req, Body: body}, nil
	}
	rule := e.rules[idx]
	res := &RewriteResult{Matched: true, Rule: idx, Pattern: rule.source, Request: req, Body: body, rule: rule}
	slog.Debug("script rule matched", "rule", idx, "pattern", rule.source, "url", target)
	if rule.rewriteRequest == nil {
		return res, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	outReq, outBody, err := e.runRequestHook(rule, req, body)
	if err != nil {
		return nil, err
	}
	res.Request, res.Body = outReq, outBody
	return res, nil
}

// HasResponseHook reports whether the rule matched by res defines a
// rewriteResponse hook. Callers use it to avoid buffering a response body when
// nothing would consume it.
func (e *Engine) HasResponseHook(res *RewriteResult) bool {
	return e != nil && res != nil && res.Matched && res.rule != nil && res.rule.rewriteResp != nil
}

// RewriteResponse applies the response hook of the rule that matched in res.
// It returns the caller's arguments untouched when res has no match or the
// matched rule defines no rewriteResponse. ContentLength, Body and the
// Content-Length header are re-derived from the rewritten body, so the body is
// materialised in memory: streaming is not preserved.
func (e *Engine) RewriteResponse(res *RewriteResult, resp *http.Response, body []byte) (*http.Response, []byte, error) {
	if e == nil {
		return nil, nil, errors.New("script: nil engine")
	}
	if res == nil || !res.Matched || res.rule == nil || res.rule.rewriteResp == nil {
		return resp, body, nil
	}
	if resp == nil {
		return nil, nil, errors.New("script: nil response")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var (
		outResp *http.Response
		outBody []byte
	)
	err := e.withInterrupt(func() error {
		jresp := responseToJS(e.vm, resp, body)
		ret, err := res.rule.rewriteResp(goja.Undefined(), jresp)
		if err != nil {
			return err
		}
		target := jresp
		if o := jsObject(ret); o != nil {
			target = o
		}
		r, b, hasBody, err := responseFromJS(target, resp)
		if err != nil {
			return err
		}
		outResp, outBody = r, body
		if hasBody {
			outBody = b
		}
		return nil
	})
	if err != nil {
		return nil, nil, e.hookError("rewriteResponse", res.rule, err)
	}
	slog.Debug("script response rewritten", "rule", res.Rule, "status", outResp.StatusCode, "bytes", len(outBody))
	return outResp, outBody, nil
}

// runRequestHook converts req to a JS object, calls the rule's rewriteRequest
// and converts the result back. The caller must hold e.mu.
func (e *Engine) runRequestHook(rule *compiledRule, req *http.Request, body []byte) (*http.Request, []byte, error) {
	var (
		outReq  *http.Request
		outBody []byte
	)
	err := e.withInterrupt(func() error {
		jreq := requestToJS(e.vm, req, body)
		ret, err := rule.rewriteRequest(goja.Undefined(), jreq)
		if err != nil {
			return err
		}
		// Mutating the argument is the common style; a returned object wins.
		target := jreq
		if o := jsObject(ret); o != nil {
			target = o
		}
		r, b, hasBody, err := requestFromJS(target, req)
		if err != nil {
			return err
		}
		outReq, outBody = r, body
		if hasBody {
			outBody = b
		}
		return nil
	})
	if err != nil {
		return nil, nil, e.hookError("rewriteRequest", rule, err)
	}
	return outReq, outBody, nil
}

// hookError annotates a hook failure, mapping an interrupted execution to
// ErrTimeout. JavaScript exceptions are logged but not treated as fatal: the
// caller decides whether to fall back to the unmodified traffic.
func (e *Engine) hookError(hook string, rule *compiledRule, err error) error {
	if errors.Is(err, ErrTimeout) {
		slog.Warn("script hook timed out", "hook", hook, "pattern", rule.source, "timeout", e.timeout)
		return fmt.Errorf("script: %s %q: %w", hook, rule.source, ErrTimeout)
	}
	slog.Warn("script hook failed", "hook", hook, "pattern", rule.source, "err", err)
	return fmt.Errorf("script: %s %q: %w", hook, rule.source, err)
}

// match returns the index of the first rule matching target, or -1.
func (e *Engine) match(target string) int {
	for i, r := range e.rules {
		if r.pattern.MatchString(target) {
			return i
		}
	}
	return -1
}

// withInterrupt runs fn with the engine timeout armed, interrupting the
// runtime when it elapses. The caller must hold e.mu; that plus the local
// timer mutex guarantees ClearInterrupt runs after any Interrupt attempt, which
// is what goja requires.
func (e *Engine) withInterrupt(fn func() error) (err error) {
	e.timedOut.Store(false)
	if e.timeout <= 0 {
		return fn()
	}

	var (
		timerMu  sync.Mutex
		disarmed bool
	)
	timer := time.AfterFunc(e.timeout, func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if disarmed {
			return
		}
		e.timedOut.Store(true)
		e.vm.Interrupt(errInterrupt)
	})
	defer func() {
		timer.Stop()
		// Wait out an Interrupt that is already in flight, then make sure no
		// further one can start before clearing the flag.
		timerMu.Lock()
		disarmed = true
		timerMu.Unlock()
		// Interrupt leaves the runtime flagged even when nothing was running;
		// without this cleanup every later call would abort immediately.
		e.vm.ClearInterrupt()
		if e.timedOut.Load() {
			err = ErrTimeout
		}
	}()

	return fn()
}

// absoluteURL renders req as an absolute URL, the string rules match against.
func absoluteURL(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	u := *req.URL
	if u.Scheme == "" {
		u.Scheme = schemeOf(req)
	}
	if u.Host == "" {
		u.Host = req.Host
	}
	return u.String()
}

// schemeOf returns the request scheme, guessing it when the request was parsed
// off the wire: such requests carry no scheme, so an explicit :80 means
// cleartext and anything else (including the implicit 443) means TLS.
func schemeOf(req *http.Request) string {
	switch {
	case req.URL != nil && req.URL.Scheme != "":
		return req.URL.Scheme
	case req.URL != nil && req.URL.Host != "":
		return "https"
	case strings.HasSuffix(req.Host, ":80"):
		return "http"
	default:
		return "https"
	}
}

// requestHost returns the authority the request is destined for.
func requestHost(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

// requestPath returns the origin-form target (path plus query) of the request.
func requestPath(req *http.Request) string {
	if req.URL == nil {
		return "/"
	}
	return req.URL.RequestURI()
}
