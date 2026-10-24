package script

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// Body encodings reported in the `bodyEncoding` field of the JS objects.
const (
	encodingUTF8   = "utf8"
	encodingBase64 = "base64"
)

// requestToJS renders req and its body as the object handed to rewriteRequest.
func requestToJS(vm *goja.Runtime, req *http.Request, body []byte) goja.Value {
	o := vm.NewObject()
	_ = o.Set("method", req.Method)
	_ = o.Set("url", absoluteURL(req))
	_ = o.Set("scheme", schemeOf(req))
	_ = o.Set("host", requestHost(req))
	_ = o.Set("path", requestPath(req))
	_ = o.Set("headers", headerToJS(vm, req.Header))
	setBodyFields(o, body)
	return o
}

// responseToJS renders resp and its body as the object handed to
// rewriteResponse.
func responseToJS(vm *goja.Runtime, resp *http.Response, body []byte) goja.Value {
	o := vm.NewObject()
	_ = o.Set("status", resp.StatusCode)
	_ = o.Set("statusText", statusTextOf(resp.Status, resp.StatusCode))
	_ = o.Set("headers", headerToJS(vm, resp.Header))
	setBodyFields(o, body)
	return o
}

// jsToRequest builds a new request from a JS object, starting from original so
// fields the script did not touch keep their value. A nil or non-object v
// yields original unchanged.
//
// Reading values needs no runtime state, so vm is unused here; it is accepted
// to mirror requestToJS and to keep room for runtime-aware conversions.
func jsToRequest(vm *goja.Runtime, v goja.Value, original *http.Request) (*http.Request, error) {
	req, _, _, err := requestFromJS(v, original)
	return req, err
}

// jsToResponse builds a new response from a JS object, starting from original
// so fields the script did not touch keep their value.
func jsToResponse(vm *goja.Runtime, v goja.Value, original *http.Response) (*http.Response, error) {
	resp, _, _, err := responseFromJS(v, original)
	return resp, err
}

// requestFromJS is the body-aware form of jsToRequest. hasBody reports whether
// the object carried a `body` field, letting the engine keep the original body
// bytes when the script had no chance to see them.
func requestFromJS(v goja.Value, original *http.Request) (*http.Request, []byte, bool, error) {
	if original == nil {
		return nil, nil, false, errors.New("script: nil original request")
	}
	obj := jsObject(v)
	if obj == nil {
		return original, nil, false, nil
	}

	out := original.Clone(original.Context())
	// RequestURI describes an inbound request; the result is outgoing.
	out.RequestURI = ""

	if mv := obj.Get("method"); isSet(mv) {
		method := strings.ToUpper(strings.TrimSpace(mv.String()))
		if method == "" {
			return nil, nil, false, errors.New("script: empty request method")
		}
		out.Method = method
	}
	if err := applyTarget(obj, out, original); err != nil {
		return nil, nil, false, err
	}
	if hv := obj.Get("headers"); isSet(hv) {
		h, err := jsToHeader(hv)
		if err != nil {
			return nil, nil, false, err
		}
		out.Header = h
	}
	if out.Header == nil {
		out.Header = make(http.Header)
	}

	body, hasBody, err := jsBody(obj)
	if err != nil {
		return nil, nil, false, err
	}
	if hasBody {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.TransferEncoding = nil
		// Framing is recomputed from the body; a stale header would be written
		// in addition to the freshly derived one.
		out.Header.Del("Content-Length")
		out.Header.Del("Transfer-Encoding")
	}
	return out, body, hasBody, nil
}

// applyTarget rewrites the destination of out. `url` is authoritative when the
// script changed it; otherwise the scheme/host/path parts are recomposed, so
// changing just `host` works as expected.
func applyTarget(obj *goja.Object, out, original *http.Request) error {
	origURL, origScheme := absoluteURL(original), schemeOf(original)
	origHost, origPath := requestHost(original), requestPath(original)

	newURL := changedString(obj, "url", origURL)
	newScheme := changedString(obj, "scheme", origScheme)
	newHost := changedString(obj, "host", origHost)
	newPath := changedString(obj, "path", origPath)

	switch {
	case newURL != origURL:
		return parseTarget(out, newURL)
	case newScheme != origScheme || newHost != origHost || newPath != origPath:
		if newPath == "" {
			newPath = "/"
		} else if !strings.HasPrefix(newPath, "/") {
			newPath = "/" + newPath
		}
		return parseTarget(out, newScheme+"://"+newHost+newPath)
	default:
		return nil
	}
}

// parseTarget parses an absolute URL into out, falling back to the existing
// scheme and authority for the parts the script left out.
func parseTarget(out *http.Request, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("script: invalid url %q: %w", raw, err)
	}
	if u.Scheme == "" {
		u.Scheme = schemeOf(out)
	}
	if u.Host != "" {
		out.Host = u.Host
	} else if out.URL != nil {
		u.Host = out.URL.Host
	}
	out.URL = u
	return nil
}

// responseFromJS is the body-aware form of jsToResponse.
func responseFromJS(v goja.Value, original *http.Response) (*http.Response, []byte, bool, error) {
	obj := jsObject(v)
	if obj == nil {
		return original, nil, false, nil
	}

	out := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	if original != nil {
		out.StatusCode = original.StatusCode
		out.Status = original.Status
		out.Proto, out.ProtoMajor, out.ProtoMinor = original.Proto, original.ProtoMajor, original.ProtoMinor
		out.Header = original.Header.Clone()
		out.Trailer = original.Trailer
		out.Close = original.Close
		out.Uncompressed = original.Uncompressed
		out.Request = original.Request
	}
	if out.Header == nil {
		out.Header = make(http.Header)
	}

	code := out.StatusCode
	if sv := obj.Get("status"); isSet(sv) {
		n := int(sv.ToInteger())
		if n < 100 || n > 999 {
			return nil, nil, false, fmt.Errorf("script: invalid response status %d", n)
		}
		code = n
	}
	// origText is the reason phrase the script saw; an unchanged statusText
	// combined with a new code must not keep it (that would print
	// "201 OK"), so the standard text for the new code wins instead.
	origText := statusTextOf(out.Status, out.StatusCode)
	text := origText
	if tv := obj.Get("statusText"); isSet(tv) {
		if s := strings.TrimSpace(tv.String()); s != "" {
			text = s
		}
	}
	if text == origText && code != out.StatusCode {
		if std := http.StatusText(code); std != "" {
			text = std
		}
	}
	out.StatusCode = code
	out.Status = strings.TrimSpace(fmt.Sprintf("%d %s", code, text))

	if hv := obj.Get("headers"); isSet(hv) {
		h, err := jsToHeader(hv)
		if err != nil {
			return nil, nil, false, err
		}
		out.Header = h
	}

	body, hasBody, err := jsBody(obj)
	if err != nil {
		return nil, nil, false, err
	}
	if hasBody {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.TransferEncoding = nil
		out.Header.Del("Content-Length")
		out.Header.Del("Transfer-Encoding")
	}
	return out, body, hasBody, nil
}

// headerToJS renders h as a plain object: a single value stays a string, a
// repeated header becomes an array of strings.
func headerToJS(vm *goja.Runtime, h http.Header) *goja.Object {
	o := vm.NewObject()
	for k, vs := range h {
		switch len(vs) {
		case 0:
			continue
		case 1:
			_ = o.Set(k, vs[0])
		default:
			_ = o.Set(k, vs)
		}
	}
	return o
}

// jsToHeader rebuilds a header map from a JS object. Values may be strings,
// numbers, booleans or arrays of those; null and undefined drop the header.
// Names are canonicalised, invalid names are skipped.
func jsToHeader(v goja.Value) (http.Header, error) {
	obj := jsObject(v)
	if obj == nil {
		return nil, errors.New("script: headers must be an object")
	}
	h := make(http.Header, len(obj.Keys()))
	for _, k := range obj.Keys() {
		name := textproto.CanonicalMIMEHeaderKey(k)
		if name == "" {
			continue
		}
		val := obj.Get(k)
		if !isSet(val) {
			continue
		}
		switch t := val.Export().(type) {
		case string:
			h[name] = []string{t}
		case []string:
			if len(t) > 0 {
				h[name] = t
			}
		case []any:
			values := make([]string, 0, len(t))
			for _, e := range t {
				if e == nil {
					continue
				}
				values = append(values, fmt.Sprint(e))
			}
			if len(values) > 0 {
				h[name] = values
			}
		case nil:
			continue
		default:
			h[name] = []string{val.String()}
		}
	}
	return h, nil
}

// setBodyFields writes the body and its encoding onto a JS object.
func setBodyFields(o *goja.Object, body []byte) {
	if utf8.Valid(body) {
		_ = o.Set("body", string(body))
		_ = o.Set("bodyEncoding", encodingUTF8)
		return
	}
	_ = o.Set("body", base64.StdEncoding.EncodeToString(body))
	_ = o.Set("bodyEncoding", encodingBase64)
}

// jsBody reads the body fields of a JS object. hasBody reports whether a body
// was present; an explicit null means "empty body".
func jsBody(obj *goja.Object) ([]byte, bool, error) {
	bv := obj.Get("body")
	if !isSet(bv) {
		if bv != nil && goja.IsNull(bv) {
			return nil, true, nil
		}
		return nil, false, nil
	}
	encoding := encodingUTF8
	if ev := obj.Get("bodyEncoding"); isSet(ev) {
		encoding = strings.ToLower(strings.TrimSpace(ev.String()))
	}
	switch encoding {
	case "", encodingUTF8:
		return []byte(bv.String()), true, nil
	case encodingBase64:
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bv.String()))
		if err != nil {
			return nil, false, fmt.Errorf("script: invalid base64 body: %w", err)
		}
		return decoded, true, nil
	default:
		return nil, false, fmt.Errorf("script: unknown bodyEncoding %q", encoding)
	}
}

// statusTextOf extracts the reason phrase from a status line, falling back to
// the standard text for the code.
func statusTextOf(status string, code int) string {
	if _, rest, ok := strings.Cut(status, " "); ok {
		return strings.TrimSpace(rest)
	}
	return http.StatusText(code)
}

// changedString returns the value of obj[name] when it is set and differs from
// fallback, and fallback otherwise.
func changedString(obj *goja.Object, name, fallback string) string {
	v := obj.Get(name)
	if !isSet(v) {
		return fallback
	}
	s := v.String()
	if s == "" {
		return fallback
	}
	return s
}

// isSet reports whether v holds a usable (not nil/undefined/null) value.
func isSet(v goja.Value) bool {
	return v != nil && !goja.IsUndefined(v) && !goja.IsNull(v)
}

// jsObject narrows v to an object, returning nil for anything else.
func jsObject(v goja.Value) *goja.Object {
	if !isSet(v) {
		return nil
	}
	o, ok := v.(*goja.Object)
	if !ok {
		return nil
	}
	return o
}
