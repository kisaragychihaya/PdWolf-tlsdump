package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/andybalholm/brotli"
)

// supportedEncodings lists the content codings the script path decodes before a
// response hook runs and re-encodes afterwards. Anything else (zstd, ...)
// is passed through untouched and left for the client to decode.
var supportedEncodings = []string{"gzip", "deflate", "br"}

// decompressBody decodes body according to the Content-Encoding value in
// encoding. It returns the decoded body and the normalised coding name, or
// (nil, "", nil) when the coding is absent or unsupported, in which case the
// body is already plain.
//
// An empty body is accepted for every coding and decodes to itself: HEAD and
// 204 responses advertise the coding the corresponding GET would use without
// carrying any body.
func decompressBody(body []byte, encoding string) ([]byte, string, error) {
	coding, ok := normaliseEncoding(encoding)
	if !ok {
		return nil, "", nil
	}
	if len(body) == 0 {
		return []byte{}, coding, nil
	}

	var (
		plain []byte
		err   error
	)
	switch coding {
	case "gzip":
		plain, err = gunzip(body)
	case "deflate":
		plain, err = inflate(body)
	case "br":
		plain, err = unbrotli(body)
	default:
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return plain, coding, nil
}

// compressBody encodes body with the given content coding.
func compressBody(body []byte, encoding string) ([]byte, error) {
	var buf bytes.Buffer
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
	case "deflate":
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return nil, fmt.Errorf("deflate: %w", err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("deflate: %w", err)
		}
	case "br":
		bw := brotli.NewWriter(&buf)
		if _, err := bw.Write(body); err != nil {
			return nil, fmt.Errorf("br: %w", err)
		}
		if err := bw.Close(); err != nil {
			return nil, fmt.Errorf("br: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	return buf.Bytes(), nil
}

// decodeRecordedBody converts a recorded response body to plaintext when its
// Content-Encoding names a supported coding. The forwarded response is
// untouched — the client still receives the original compressed bytes; only
// the JSONL record is decoded. Truncated (record-limit) or undecodable bodies
// are returned unchanged, so the record keeps the raw bytes it captured.
// Decoded plaintext is re-capped at the record body limit.
func decodeRecordedBody(raw []byte, truncated bool, encoding string, limit int64) ([]byte, bool) {
	if truncated {
		return raw, truncated
	}
	plain, coding, err := decompressBody(raw, encoding)
	if err != nil {
		slog.Warn("record: response decompression failed, recording original bytes", "encoding", encoding, "err", err)
		return raw, truncated
	}
	if coding == "" {
		return raw, truncated
	}
	lb := &limitedBuffer{limit: limit}
	_, _ = lb.Write(plain)
	return lb.bytes(), lb.truncated()
}

// normaliseEncoding lowercases encoding and reports whether it names a coding
// we handle. Only a single coding is accepted: a compound value such as
// "gzip, br" is left to the client.
func normaliseEncoding(encoding string) (string, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	for _, supported := range supportedEncodings {
		if enc == supported {
			return enc, true
		}
	}
	return "", false
}

// gunzip decodes a gzip stream.
func gunzip(body []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	plain, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	return plain, nil
}

// unbrotli decodes a brotli stream.
func unbrotli(body []byte) ([]byte, error) {
	zr := brotli.NewReader(bytes.NewReader(body))
	plain, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("br: %w", err)
	}
	return plain, nil
}

// inflate decodes a zlib-wrapped DEFLATE stream. The HTTP spec requires the
// zlib wrapper, but plenty of servers emit raw DEFLATE, so that is accepted as
// a fallback.
func inflate(body []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err == nil {
		defer zr.Close()
		plain, readErr := io.ReadAll(zr)
		if readErr == nil {
			return plain, nil
		}
		err = readErr
	}

	fr := flate.NewReader(bytes.NewReader(body))
	defer fr.Close()
	plain, flateErr := io.ReadAll(fr)
	if flateErr != nil {
		return nil, fmt.Errorf("zlib: %v; raw: %w", err, flateErr)
	}
	return plain, nil
}
