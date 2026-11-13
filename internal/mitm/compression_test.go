package mitm

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/andybalholm/brotli"

	"tlsdump/internal/script"
)

const testPlaintext = "hello, tlsdump! " // repetitive enough to compress well

func TestDecompressBodyGzip(t *testing.T) {
	compressed := gzipBody(t, testPlaintext)
	plain, encoding, err := decompressBody(compressed, "gzip")
	if err != nil {
		t.Fatalf("decompressBody: %v", err)
	}
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip", encoding)
	}
	if string(plain) != testPlaintext {
		t.Fatalf("plain = %q, want %q", plain, testPlaintext)
	}
}

func TestDecompressBodyDeflate(t *testing.T) {
	compressed := zlibBody(t, testPlaintext)
	plain, encoding, err := decompressBody(compressed, "deflate")
	if err != nil {
		t.Fatalf("decompressBody: %v", err)
	}
	if encoding != "deflate" {
		t.Fatalf("encoding = %q, want deflate", encoding)
	}
	if string(plain) != testPlaintext {
		t.Fatalf("plain = %q, want %q", plain, testPlaintext)
	}
}

// Some servers send raw DEFLATE despite the zlib wrapper the spec requires.
func TestDecompressBodyRawDeflate(t *testing.T) {
	compressed := flateBody(t, testPlaintext)
	plain, encoding, err := decompressBody(compressed, "deflate")
	if err != nil {
		t.Fatalf("decompressBody: %v", err)
	}
	if encoding != "deflate" {
		t.Fatalf("encoding = %q, want deflate", encoding)
	}
	if string(plain) != testPlaintext {
		t.Fatalf("plain = %q, want %q", plain, testPlaintext)
	}
}

func TestDecompressBodyBrotli(t *testing.T) {
	compressed := brotliBody(t, testPlaintext)
	plain, encoding, err := decompressBody(compressed, "br")
	if err != nil {
		t.Fatalf("decompressBody: %v", err)
	}
	if encoding != "br" {
		t.Fatalf("encoding = %q, want br", encoding)
	}
	if string(plain) != testPlaintext {
		t.Fatalf("plain = %q, want %q", plain, testPlaintext)
	}
}

func TestDecompressBodyUnhandledEncodings(t *testing.T) {
	raw := []byte("not really compressed")
	for _, enc := range []string{"", "identity", "zstd", "gzip, br"} {
		t.Run(enc, func(t *testing.T) {
			plain, encoding, err := decompressBody(raw, enc)
			if err != nil {
				t.Fatalf("decompressBody(%q): %v", enc, err)
			}
			if plain != nil {
				t.Fatalf("plain = %q, want nil for unsupported encoding", plain)
			}
			if encoding != "" {
				t.Fatalf("encoding = %q, want empty", encoding)
			}
		})
	}
}

// HEAD/204 responses advertise a coding without carrying a body.
func TestDecompressBodyEmpty(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate", "br"} {
		t.Run(enc, func(t *testing.T) {
			plain, encoding, err := decompressBody(nil, enc)
			if err != nil {
				t.Fatalf("decompressBody: %v", err)
			}
			if len(plain) != 0 {
				t.Fatalf("plain = %q, want empty", plain)
			}
			if encoding != enc {
				t.Fatalf("encoding = %q, want %q", encoding, enc)
			}
		})
	}
}

func TestDecompressBodyCaseInsensitive(t *testing.T) {
	compressed := gzipBody(t, testPlaintext)
	plain, encoding, err := decompressBody(compressed, " GZIP ")
	if err != nil {
		t.Fatalf("decompressBody: %v", err)
	}
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip", encoding)
	}
	if string(plain) != testPlaintext {
		t.Fatalf("plain = %q, want %q", plain, testPlaintext)
	}
}

func TestDecompressBodyInvalidData(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{name: "gzip", encoding: "gzip", body: []byte("definitely not gzip")},
		{name: "gzip truncated", encoding: "gzip", body: gzipBody(t, testPlaintext)[:6]},
		{name: "deflate", encoding: "deflate", body: []byte("definitely not deflate")},
		{name: "br", encoding: "br", body: []byte("definitely not brotli")},
		{name: "br truncated", encoding: "br", body: brotliBody(t, testPlaintext)[:6]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decompressBody(tc.body, tc.encoding); err == nil {
				t.Fatal("decompressBody succeeded on invalid data, want error")
			}
		})
	}
}

func TestCompressBodyRoundTrip(t *testing.T) {
	for _, enc := range supportedEncodings {
		t.Run(enc, func(t *testing.T) {
			compressed, err := compressBody([]byte(testPlaintext), enc)
			if err != nil {
				t.Fatalf("compressBody: %v", err)
			}
			if bytes.Equal(compressed, []byte(testPlaintext)) {
				t.Fatal("compressBody returned the input unchanged")
			}
			plain, encoding, err := decompressBody(compressed, enc)
			if err != nil {
				t.Fatalf("decompressBody: %v", err)
			}
			if encoding != enc {
				t.Fatalf("encoding = %q, want %q", encoding, enc)
			}
			if string(plain) != testPlaintext {
				t.Fatalf("plain = %q, want %q", plain, testPlaintext)
			}
		})
	}
}

func TestDecodeRecordedBody(t *testing.T) {
	t.Run("supported codings decode to plaintext", func(t *testing.T) {
		for _, tc := range []struct {
			encoding string
			compress func(*testing.T, string) []byte
		}{
			{encoding: "gzip", compress: gzipBody},
			{encoding: "deflate", compress: zlibBody},
			{encoding: "br", compress: brotliBody},
		} {
			raw := tc.compress(t, testPlaintext)
			plain, trunc := decodeRecordedBody(raw, false, tc.encoding, 1<<20)
			if trunc {
				t.Fatalf("%s: truncated = true, want false", tc.encoding)
			}
			if string(plain) != testPlaintext {
				t.Fatalf("%s: plain = %q, want %q", tc.encoding, plain, testPlaintext)
			}
		}
	})

	t.Run("absent or unsupported coding keeps raw", func(t *testing.T) {
		for _, enc := range []string{"", "identity", "zstd", "gzip, br"} {
			raw := gzipBody(t, testPlaintext)
			plain, trunc := decodeRecordedBody(raw, false, enc, 1<<20)
			if trunc || !bytes.Equal(plain, raw) {
				t.Fatalf("encoding %q: body changed (trunc=%v)", enc, trunc)
			}
		}
	})

	t.Run("truncated keeps raw", func(t *testing.T) {
		raw := gzipBody(t, testPlaintext)
		plain, trunc := decodeRecordedBody(raw, true, "gzip", 1<<20)
		if !trunc || !bytes.Equal(plain, raw) {
			t.Fatalf("truncated input must be recorded raw, got trunc=%v body=%q", trunc, plain)
		}
	})

	t.Run("undecodable keeps raw", func(t *testing.T) {
		raw := []byte("claims to be gzip but is not")
		plain, trunc := decodeRecordedBody(raw, false, "gzip", 1<<20)
		if trunc || !bytes.Equal(plain, raw) {
			t.Fatalf("undecodable input must be recorded raw, got trunc=%v body=%q", trunc, plain)
		}
	})

	t.Run("plaintext re-capped at limit", func(t *testing.T) {
		raw := gzipBody(t, testPlaintext)
		plain, trunc := decodeRecordedBody(raw, false, "gzip", 5)
		if !trunc {
			t.Fatal("truncated = false, want true once plaintext exceeds the limit")
		}
		if len(plain) != 5 || string(plain) != testPlaintext[:5] {
			t.Fatalf("plain = %q, want first 5 bytes", plain)
		}
	})
}

func TestCompressBodyUnsupported(t *testing.T) {
	if _, err := compressBody([]byte(testPlaintext), "zstd"); err == nil {
		t.Fatal("compressBody accepted an unsupported encoding")
	}
}

func TestRewriteResponseDecompressesForScript(t *testing.T) {
	for _, tc := range []struct {
		encoding string
		compress func(*testing.T, string) []byte
	}{
		{encoding: "gzip", compress: gzipBody},
		{encoding: "br", compress: brotliBody},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			engine := newTestEngine(t, `
var rules = [{
  pattern: ".*",
  rewriteResponse: function (resp) {
    resp.body = resp.body.replace("hello", "world");
  }
}];
`)
			const upstreamPlain = `{"message":"hello"}`
			const wantPlain = `{"message":"world"}`
			upstreamBody := tc.compress(t, upstreamPlain)

			h := &Handler{ScriptEngine: engine}
			req := mustRequest(t, http.MethodGet, "https://example.com/api")
			res := matchRequest(t, engine, req)

			resp := &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Encoding": {tc.encoding}, "Content-Length": {strconv.Itoa(len(upstreamBody))}, "Content-Type": {"application/json"}},
				Body:          io.NopCloser(bytes.NewReader(upstreamBody)),
				ContentLength: int64(len(upstreamBody)),
			}

			out, recordBody, buffered := h.rewriteResponse(res, resp)
			if !buffered {
				t.Fatal("buffered = false, want true")
			}
			if string(recordBody) != wantPlain {
				t.Fatalf("recorded body = %q, want plaintext %q", recordBody, wantPlain)
			}
			if got := out.Header.Get("Content-Encoding"); got != tc.encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tc.encoding)
			}
			if got := out.Header.Get("Content-Length"); got != "" {
				t.Fatalf("Content-Length header should be re-derived, got %q", got)
			}

			sentBody, err := io.ReadAll(out.Body)
			if err != nil {
				t.Fatalf("read rewritten body: %v", err)
			}
			if out.ContentLength != int64(len(sentBody)) {
				t.Fatalf("ContentLength = %d, want %d", out.ContentLength, len(sentBody))
			}
			if bytes.Equal(sentBody, []byte(wantPlain)) {
				t.Fatal("outgoing body is plaintext, want re-compressed bytes")
			}
			if string(sentBody) == string(upstreamBody) {
				t.Fatal("outgoing body was not re-compressed after the rewrite")
			}

			// The client must be able to decode exactly what it receives.
			decoded, _, err := decompressBody(sentBody, tc.encoding)
			if err != nil {
				t.Fatalf("client-side decompression: %v", err)
			}
			if string(decoded) != wantPlain {
				t.Fatalf("decoded body = %q, want %q", decoded, wantPlain)
			}

			// And the framing on the wire must match: a single, correct Content-Length.
			out.Body = io.NopCloser(bytes.NewReader(sentBody))
			req.Method = http.MethodGet
			var wire bytes.Buffer
			if err := out.Write(&wire); err != nil {
				t.Fatalf("write response: %v", err)
			}
			parsed, err := http.ReadResponse(bufio.NewReader(&wire), req)
			if err != nil {
				t.Fatalf("read written response: %v", err)
			}
			defer parsed.Body.Close()
			if parsed.ContentLength != int64(len(sentBody)) {
				t.Fatalf("wire Content-Length = %d, want %d", parsed.ContentLength, len(sentBody))
			}
			if got := parsed.Header.Get("Content-Encoding"); got != tc.encoding {
				t.Fatalf("wire Content-Encoding = %q, want %q", got, tc.encoding)
			}
			wireBody, err := io.ReadAll(parsed.Body)
			if err != nil {
				t.Fatalf("read wire body: %v", err)
			}
			decoded, _, err = decompressBody(wireBody, tc.encoding)
			if err != nil {
				t.Fatalf("decode wire body: %v", err)
			}
			if string(decoded) != wantPlain {
				t.Fatalf("wire body decoded = %q, want %q", decoded, wantPlain)
			}
		})
	}
}

func TestRewriteResponseDecompressionFailureFallsBack(t *testing.T) {
	engine := newTestEngine(t, `
var rules = [{
  pattern: ".*",
  rewriteResponse: function (resp) {
    resp.headers["X-Hook-Ran"] = "1";
  }
}];
`)
	raw := []byte("this claims to be gzip but is not")

	h := &Handler{ScriptEngine: engine}
	req := mustRequest(t, http.MethodGet, "https://example.com/api")
	res := matchRequest(t, engine, req)

	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Encoding": {"gzip"}},
		Body:          io.NopCloser(bytes.NewReader(raw)),
		ContentLength: int64(len(raw)),
	}

	out, recordBody, buffered := h.rewriteResponse(res, resp)
	if !buffered {
		t.Fatal("buffered = false, want true")
	}
	if !bytes.Equal(recordBody, raw) {
		t.Fatalf("recorded body = %q, want the original bytes", recordBody)
	}
	if got := out.Header.Get("X-Hook-Ran"); got != "" {
		t.Fatal("response hook ran on an undecodable body")
	}
	if got := out.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip preserved", got)
	}
	sent, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(sent, raw) {
		t.Fatalf("body = %q, want original bytes forwarded", sent)
	}
}

func TestRewriteResponseWithoutResponseHookStreams(t *testing.T) {
	engine := newTestEngine(t, `
var rules = [{
  pattern: ".*",
  rewriteRequest: function (req) { req.headers["X-Request"] = "1"; }
}];
`)
	raw := gzipBody(t, testPlaintext)

	h := &Handler{ScriptEngine: engine}
	req := mustRequest(t, http.MethodGet, "https://example.com/api")
	res := matchRequest(t, engine, req)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Encoding": {"gzip"}},
		Body:       io.NopCloser(bytes.NewReader(raw)),
	}

	out, recordBody, buffered := h.rewriteResponse(res, resp)
	if buffered {
		t.Fatal("buffered = true without a response hook")
	}
	if recordBody != nil {
		t.Fatalf("recordBody = %q, want nil", recordBody)
	}
	if out != resp {
		t.Fatal("response was replaced without a response hook")
	}
	if got := out.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip untouched", got)
	}
}

func newTestEngine(t *testing.T, src string) *script.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.js")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	engine, err := script.NewEngine(path, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func matchRequest(t *testing.T, engine *script.Engine, req *http.Request) *script.RewriteResult {
	t.Helper()
	res, err := engine.MatchAndRewrite(req, nil)
	if err != nil {
		t.Fatalf("MatchAndRewrite: %v", err)
	}
	return res
}

func gzipBody(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zlibBody(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func flateBody(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate NewWriter: %v", err)
	}
	if _, err := fw.Write([]byte(s)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func brotliBody(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write([]byte(s)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}
