package event

import (
	"bytes"
	"strconv"
	"strings"
)

// ParsedHTTP represents a parsed HTTP/1.x request or response extracted from TLS plaintext.
type ParsedHTTP struct {
	IsRequest  bool              `json:"is_request"`
	Method     string            `json:"method,omitempty"`
	URI        string            `json:"uri,omitempty"`
	Proto      string            `json:"proto,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	StatusText string            `json:"status_text,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
}

var httpMethods = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ",
}

// TryParseHTTP attempts to parse an HTTP request or response from raw TLS data.
// Returns nil if the data does not look like a valid HTTP message.
func TryParseHTTP(data []byte) *ParsedHTTP {
	if len(data) < 16 {
		return nil
	}

	// Check for HTTP response
	if bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return parseResponse(data)
	}

	// Check for HTTP request
	for _, method := range httpMethods {
		if bytes.HasPrefix(data, []byte(method)) {
			return parseRequest(data)
		}
	}

	return nil
}

func parseRequest(data []byte) *ParsedHTTP {
	// Find end of headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil
	}

	headerPart := string(data[:headerEnd])
	body := data[headerEnd+4:]

	// Parse request line
	lines := strings.Split(headerPart, "\r\n")
	if len(lines) < 1 {
		return nil
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		return nil
	}

	headers := parseHeaders(lines[1:])

	return &ParsedHTTP{
		IsRequest: true,
		Method:    parts[0],
		URI:       parts[1],
		Proto:     parts[2],
		Headers:   headers,
		Body:      body,
	}
}

func parseResponse(data []byte) *ParsedHTTP {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil
	}

	headerPart := string(data[:headerEnd])
	body := data[headerEnd+4:]

	lines := strings.Split(headerPart, "\r\n")
	if len(lines) < 1 {
		return nil
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return nil
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}

	statusText := ""
	if len(parts) >= 3 {
		statusText = parts[2]
	}

	headers := parseHeaders(lines[1:])

	return &ParsedHTTP{
		IsRequest:  false,
		Proto:      parts[0],
		StatusCode: statusCode,
		StatusText: statusText,
		Headers:    headers,
		Body:       body,
	}
}

func parseHeaders(lines []string) map[string]string {
	headers := make(map[string]string, len(lines))
	for _, line := range lines {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		headers[name] = value
	}
	return headers
}
