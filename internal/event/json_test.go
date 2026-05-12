package event

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestJSONWriter_OutputFormat(t *testing.T) {
	var buf bytes.Buffer
	jw := newJSONWriter(&buf)

	ev := &AssembledEvent{
		PID:       1234,
		TID:       5678,
		Comm:      "curl",
		Direction: DirSend,
		Timestamp: time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		Data:      []byte("Hello TLS"),
	}
	jw.Write(ev)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, buf.String())
	}

	if result["pid"].(float64) != 1234 {
		t.Errorf("expected pid 1234, got %v", result["pid"])
	}
	if result["tid"].(float64) != 5678 {
		t.Errorf("expected tid 5678, got %v", result["tid"])
	}
	if result["comm"].(string) != "curl" {
		t.Errorf("expected comm curl, got %v", result["comm"])
	}
	if result["direction"].(string) != "SEND" {
		t.Errorf("expected direction SEND, got %v", result["direction"])
	}
	if result["length"].(float64) != 9 {
		t.Errorf("expected length 9, got %v", result["length"])
	}
	if result["data_hex"].(string) != "48656c6c6f20544c53" {
		t.Errorf("expected data_hex 48656c6c6f20544c53, got %v", result["data_hex"])
	}
}

func TestJSONWriter_RecvDirection(t *testing.T) {
	var buf bytes.Buffer
	jw := newJSONWriter(&buf)

	ev := &AssembledEvent{
		PID:       100,
		TID:       200,
		Comm:      "wget",
		Direction: DirRecv,
		Timestamp: time.Now(),
		Data:      []byte("response"),
	}
	jw.Write(ev)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result["direction"].(string) != "RECV" {
		t.Errorf("expected direction RECV, got %v", result["direction"])
	}
}

func TestJSONWriter_WithHTTP(t *testing.T) {
	var buf bytes.Buffer
	jw := newJSONWriter(&buf)

	ev := &AssembledEvent{
		PID:       100,
		TID:       200,
		Comm:      "curl",
		Direction: DirSend,
		Timestamp: time.Now(),
		Data:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		HTTP: &ParsedHTTP{
			IsRequest: true,
			Method:    "GET",
			URI:       "/",
			Proto:     "HTTP/1.1",
			Headers:   map[string]string{"Host": "example.com"},
		},
	}
	jw.Write(ev)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	httpObj, ok := result["http"].(map[string]interface{})
	if !ok {
		t.Fatal("expected http field to be an object")
	}
	if httpObj["method"].(string) != "GET" {
		t.Errorf("expected http.method GET, got %v", httpObj["method"])
	}
	if httpObj["uri"].(string) != "/" {
		t.Errorf("expected http.uri /, got %v", httpObj["uri"])
	}
}

func TestJSONWriter_JSONLinesFormat(t *testing.T) {
	var buf bytes.Buffer
	jw := newJSONWriter(&buf)

	for i := 0; i < 3; i++ {
		ev := &AssembledEvent{
			PID:       uint32(i),
			TID:       100,
			Comm:      "test",
			Direction: DirSend,
			Timestamp: time.Now(),
			Data:      []byte("data"),
		}
		jw.Write(ev)
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var result map[string]interface{}
		if err := json.Unmarshal(line, &result); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestJSONWriter_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	jw := newJSONWriter(&buf)

	ev := &AssembledEvent{
		PID:       1,
		TID:       1,
		Comm:      "test",
		Direction: DirRecv,
		Timestamp: time.Now(),
		Data:      []byte{},
	}
	jw.Write(ev)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result["length"].(float64) != 0 {
		t.Errorf("expected length 0, got %v", result["length"])
	}
	if result["data_hex"].(string) != "" {
		t.Errorf("expected empty data_hex, got %v", result["data_hex"])
	}
}
