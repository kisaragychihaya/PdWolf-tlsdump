// Package record serializes intercepted HTTP requests/responses as JSONL.
package record

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

// Entry is a single recorded request/response pair.
type Entry struct {
	Time        time.Time   `json:"time"`
	Client      string      `json:"client"`
	Mode        string      `json:"mode"` // "mitm" or "http"
	Host        string      `json:"host"`
	Method      string      `json:"method,omitempty"`
	URI         string      `json:"uri,omitempty"`
	Status      int         `json:"status,omitempty"`
	ReqHeaders  http.Header `json:"req_headers,omitempty"`
	RespHeaders http.Header `json:"resp_headers,omitempty"`
	ReqBody     string      `json:"req_body,omitempty"`
	RespBody    string      `json:"resp_body,omitempty"`
	ReqTrunc    bool        `json:"req_body_truncated,omitempty"`
	RespTrunc   bool        `json:"resp_body_truncated,omitempty"`
}

// Logger writes one JSON object per line. Writes are serialized with a mutex.
type Logger struct {
	mu        sync.Mutex
	enc       *json.Encoder
	bodyLimit int64
}

// New returns a Logger writing to w, capturing at most bodyLimit bytes of
// each request/response body.
func New(w io.Writer, bodyLimit int64) *Logger {
	return &Logger{enc: json.NewEncoder(w), bodyLimit: bodyLimit}
}

// BodyLimit returns the per-body capture limit.
func (l *Logger) BodyLimit() int64 { return l.bodyLimit }

// Log writes e as a single JSON line.
func (l *Logger) Log(e *Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

// ReadBody reads r to EOF (draining it, so connections can be reused) while
// retaining at most limit bytes. truncated is true when the body exceeded
// limit. The returned slice holds the raw (unencoded) bytes.
func ReadBody(r io.Reader, limit int64) (raw []byte, truncated bool, err error) {
	raw = make([]byte, 0, min(limit+1, 1<<20))
	tmp := make([]byte, 4096)
	var seen int64
	for {
		n, rerr := r.Read(tmp)
		seen += int64(n)
		if room := limit - int64(len(raw)); room > 0 {
			take := tmp[:n]
			if int64(len(take)) > room {
				take = take[:room]
			}
			raw = append(raw, take...)
		}
		if rerr != nil {
			if rerr != io.EOF {
				err = rerr
			}
			break
		}
	}
	if seen > limit {
		truncated = true
	}
	return raw, truncated, err
}

// EncodeBody converts raw body bytes to the JSON string form: plain UTF-8
// text as-is, anything else base64 encoded.
func EncodeBody(raw []byte) string {
	if !utf8.Valid(raw) {
		return base64.StdEncoding.EncodeToString(raw)
	}
	return string(raw)
}
