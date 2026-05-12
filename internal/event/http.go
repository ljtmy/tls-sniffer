package event

import (
	"bytes"
	"strconv"
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
	// Find end of headers (support both CRLF and LF-only)
	headerEnd, lineSep, delimLen := findHeaderEnd(data)
	if headerEnd < 0 {
		return nil
	}

	headerPart := data[:headerEnd]
	body := data[headerEnd+delimLen:]

	// Parse request line
	lines := bytes.Split(headerPart, lineSep)
	if len(lines) < 1 {
		return nil
	}

	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 3 {
		return nil
	}

	headers := parseHeaders(lines[1:])

	return &ParsedHTTP{
		IsRequest: true,
		Method:    string(parts[0]),
		URI:       string(parts[1]),
		Proto:     string(parts[2]),
		Headers:   headers,
		Body:      body,
	}
}

func parseResponse(data []byte) *ParsedHTTP {
	headerEnd, lineSep, delimLen := findHeaderEnd(data)
	if headerEnd < 0 {
		return nil
	}

	headerPart := data[:headerEnd]
	body := data[headerEnd+delimLen:]

	lines := bytes.Split(headerPart, lineSep)
	if len(lines) < 1 {
		return nil
	}

	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return nil
	}

	statusCode, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return nil
	}

	statusText := ""
	if len(parts) >= 3 {
		statusText = string(parts[2])
	}

	headers := parseHeaders(lines[1:])

	return &ParsedHTTP{
		IsRequest:  false,
		Proto:      string(parts[0]),
		StatusCode: statusCode,
		StatusText: statusText,
		Headers:    headers,
		Body:       body,
	}
}

// findHeaderEnd finds the end of HTTP headers, supporting both CRLF and LF-only.
// Returns (headerEnd, lineSeparator, delimiterLength).
func findHeaderEnd(data []byte) (int, []byte, int) {
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		return idx, []byte("\r\n"), 4
	}
	if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		return idx, []byte("\n"), 2
	}
	return -1, nil, 0
}

func parseHeaders(lines [][]byte) map[string]string {
	headers := make(map[string]string, len(lines))
	for _, line := range lines {
		idx := bytes.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:idx]))
		value := string(bytes.TrimSpace(line[idx+1:]))
		headers[name] = value
	}
	return headers
}
