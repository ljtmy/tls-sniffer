package event

import (
	"testing"
)

func TestTryParseHTTP_NilForShortData(t *testing.T) {
	result := TryParseHTTP([]byte("short"))
	if result != nil {
		t.Error("expected nil for data shorter than 16 bytes")
	}
}

func TestTryParseHTTP_NilForNonHTTP(t *testing.T) {
	result := TryParseHTTP([]byte("this is not http data at all!!"))
	if result != nil {
		t.Error("expected nil for non-HTTP data")
	}
}

func TestTryParseHTTP_GETRequest(t *testing.T) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88\r\n\r\n")
	result := TryParseHTTP(data)
	if result == nil {
		t.Fatal("expected non-nil for GET request")
	}
	if !result.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if result.Method != "GET" {
		t.Errorf("expected method GET, got %s", result.Method)
	}
	if result.URI != "/index.html" {
		t.Errorf("expected URI /index.html, got %s", result.URI)
	}
	if result.Proto != "HTTP/1.1" {
		t.Errorf("expected proto HTTP/1.1, got %s", result.Proto)
	}
	if result.Headers["Host"] != "example.com" {
		t.Errorf("expected Host header example.com, got %s", result.Headers["Host"])
	}
	if result.Headers["User-Agent"] != "curl/7.88" {
		t.Errorf("expected User-Agent curl/7.88, got %s", result.Headers["User-Agent"])
	}
}

func TestTryParseHTTP_POSTRequest(t *testing.T) {
	data := []byte("POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}")
	result := TryParseHTTP(data)
	if result == nil {
		t.Fatal("expected non-nil for POST request")
	}
	if !result.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if result.Method != "POST" {
		t.Errorf("expected method POST, got %s", result.Method)
	}
	if string(result.Body) != `{"key":"val"}` {
		t.Errorf("expected body {\"key\":\"val\"}, got %s", string(result.Body))
	}
}

func TestTryParseHTTP_Response(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!")
	result := TryParseHTTP(data)
	if result == nil {
		t.Fatal("expected non-nil for HTTP response")
	}
	if result.IsRequest {
		t.Error("expected IsRequest=false")
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if result.StatusText != "OK" {
		t.Errorf("expected status text OK, got %s", result.StatusText)
	}
	if result.Proto != "HTTP/1.1" {
		t.Errorf("expected proto HTTP/1.1, got %s", result.Proto)
	}
	if result.Headers["Content-Type"] != "text/html" {
		t.Errorf("expected Content-Type text/html, got %s", result.Headers["Content-Type"])
	}
	if string(result.Body) != "Hello, World!" {
		t.Errorf("expected body 'Hello, World!', got %s", string(result.Body))
	}
}

func TestTryParseHTTP_Response404(t *testing.T) {
	data := []byte("HTTP/1.1 404 Not Found\r\n\r\n")
	result := TryParseHTTP(data)
	if result == nil {
		t.Fatal("expected non-nil for 404 response")
	}
	if result.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", result.StatusCode)
	}
	if result.StatusText != "Not Found" {
		t.Errorf("expected status text 'Not Found', got %s", result.StatusText)
	}
}

func TestTryParseHTTP_ResponseNoBody(t *testing.T) {
	data := []byte("HTTP/1.1 304 Not Modified\r\nCache-Control: max-age=3600\r\n\r\n")
	result := TryParseHTTP(data)
	if result == nil {
		t.Fatal("expected non-nil for 304 response")
	}
	if result.StatusCode != 304 {
		t.Errorf("expected status 304, got %d", result.StatusCode)
	}
	if len(result.Body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(result.Body))
	}
}

func TestTryParseHTTP_AllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	for _, m := range methods {
		data := []byte(m + " /path HTTP/1.1\r\nHost: x.com\r\n\r\n")
		result := TryParseHTTP(data)
		if result == nil {
			t.Errorf("expected non-nil for %s request", m)
			continue
		}
		if result.Method != m {
			t.Errorf("expected method %s, got %s", m, result.Method)
		}
	}
}

func TestTryParseHTTP_NoCRLF(t *testing.T) {
	// Missing double CRLF separator
	data := []byte("GET /path HTTP/1.1\nHost: x.com\n\n")
	result := TryParseHTTP(data)
	if result != nil {
		t.Error("expected nil for LF-only line endings (no CRLF)")
	}
}
