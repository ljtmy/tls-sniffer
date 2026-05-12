package event

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// StdoutWriter prints assembled TLS events to stdout.
type StdoutWriter struct {
	w io.Writer
}

func NewStdoutWriter() *StdoutWriter {
	return &StdoutWriter{w: os.Stdout}
}

func (sw *StdoutWriter) Write(ev *AssembledEvent) {
	fmt.Fprintf(sw.w, "\n--- TLS %s ---\n", ev.DirectionString())
	fmt.Fprintf(sw.w, "Time: %s\n", ev.Timestamp.Format("2006-01-02 15:04:05.000"))
	fmt.Fprintf(sw.w, "PID: %d  TID: %d  COMM: %s  Len: %d\n",
		ev.PID, ev.TID, ev.Comm, len(ev.Data))

	if ev.HTTP != nil {
		fmt.Fprintf(sw.w, "HTTP: ")
		if ev.HTTP.IsRequest {
			fmt.Fprintf(sw.w, "%s %s %s\n", ev.HTTP.Method, ev.HTTP.URI, ev.HTTP.Proto)
		} else {
			fmt.Fprintf(sw.w, "%s %d %s\n", ev.HTTP.Proto, ev.HTTP.StatusCode, ev.HTTP.StatusText)
		}
		for k, v := range ev.HTTP.Headers {
			fmt.Fprintf(sw.w, "  %s: %s\n", k, v)
		}
		if len(ev.HTTP.Body) > 0 {
			fmt.Fprintf(sw.w, "  Body (%d bytes)\n", len(ev.HTTP.Body))
		}
	}

	// Try to print as text
	fmt.Fprintf(sw.w, "Data (text):\n%s\n", string(ev.Data))

	// Hex dump
	fmt.Fprintf(sw.w, "Data (hex):\n%s\n", hex.Dump(ev.Data))
}

func (sw *StdoutWriter) Close() error {
	return nil
}
