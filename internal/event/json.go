package event

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// jsonEvent is the JSON-serializable representation of an AssembledEvent.
type jsonEvent struct {
	Timestamp string       `json:"timestamp"`
	PID       uint32       `json:"pid"`
	TID       uint32       `json:"tid"`
	Comm      string       `json:"comm"`
	Direction string       `json:"direction"`
	Length    int          `json:"length"`
	DataHex   string       `json:"data_hex"`
	HTTP      *ParsedHTTP  `json:"http,omitempty"`
}

// JSONWriter writes assembled TLS events as JSON Lines (one JSON object per line).
type JSONWriter struct {
	w io.Writer
}

func NewJSONWriter() *JSONWriter {
	return &JSONWriter{w: os.Stdout}
}

func (jw *JSONWriter) Write(ev *AssembledEvent) {
	je := jsonEvent{
		Timestamp: ev.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		PID:       ev.PID,
		TID:       ev.TID,
		Comm:      ev.Comm,
		Direction: ev.DirectionString(),
		Length:    len(ev.Data),
		DataHex:   hex.EncodeToString(ev.Data),
		HTTP:      ev.HTTP,
	}

	data, err := json.Marshal(je)
	if err != nil {
		return
	}
	fmt.Fprintln(jw.w, string(data))
}

func (jw *JSONWriter) Close() error {
	return nil
}
