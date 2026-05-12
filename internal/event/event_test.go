package event

import (
	"testing"
	"time"
)

func newTestEvent(pid, tid uint32, sslPtr uint64, dir uint32, data []byte) *TLSEvent {
	ev := &TLSEvent{
		Timestamp: uint64(time.Now().UnixNano()),
		PID:       pid,
		TID:       tid,
		Direction: dir,
		SSLPTR:    sslPtr,
		EventType: EventData,
	}
	copy(ev.Comm[:], []byte("test"))
	ev.DataLen = uint32(len(data))
	copy(ev.Data[:], data)
	return ev
}

func drainOutput(ch chan *AssembledEvent) []*AssembledEvent {
	var result []*AssembledEvent
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return result
			}
			result = append(result, ev)
		default:
			return result
		}
	}
}

func TestAssembler_SingleEvent(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("hello")))
	events := drainOutput(a.Output)

	if len(events) != 0 {
		t.Error("expected no output before flush (same direction)")
	}

	a.FlushAll()
	events = drainOutput(a.Output)

	if len(events) != 1 {
		t.Fatalf("expected 1 event after flush, got %d", len(events))
	}
	if string(events[0].Data) != "hello" {
		t.Errorf("expected data 'hello', got '%s'", string(events[0].Data))
	}
}

func TestAssembler_MergePartialReads(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("hel")))
	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("lo ")))
	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("world")))

	events := drainOutput(a.Output)
	if len(events) != 0 {
		t.Error("expected no output yet (same direction)")
	}

	a.FlushAll()
	events = drainOutput(a.Output)

	if len(events) != 1 {
		t.Fatalf("expected 1 merged event, got %d", len(events))
	}
	if string(events[0].Data) != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", string(events[0].Data))
	}
}

func TestAssembler_DirectionSwitch(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("request")))
	events := drainOutput(a.Output)
	if len(events) != 0 {
		t.Error("expected no output yet")
	}

	// Direction switch: should flush SEND, start RECV
	a.Feed(newTestEvent(1, 1, 0x1000, DirRecv, []byte("response")))
	events = drainOutput(a.Output)
	if len(events) != 1 {
		t.Fatalf("expected 1 flushed event on direction switch, got %d", len(events))
	}
	if string(events[0].Data) != "request" {
		t.Errorf("expected flushed data 'request', got '%s'", string(events[0].Data))
	}
	if events[0].Direction != DirSend {
		t.Error("expected flushed event to be SEND")
	}
}

func TestAssembler_SeparateStreams(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	// Two different SSL pointers = two streams
	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("stream1")))
	a.Feed(newTestEvent(1, 1, 0x2000, DirSend, []byte("stream2")))

	events := drainOutput(a.Output)
	if len(events) != 0 {
		t.Error("expected no output yet")
	}

	a.FlushAll()
	events = drainOutput(a.Output)

	if len(events) != 2 {
		t.Fatalf("expected 2 events (separate streams), got %d", len(events))
	}

	dataSet := make(map[string]bool)
	for _, ev := range events {
		dataSet[string(ev.Data)] = true
	}
	if !dataSet["stream1"] || !dataSet["stream2"] {
		t.Errorf("expected both 'stream1' and 'stream2', got %v", dataSet)
	}
}

func TestAssembler_SSLPTRPreserved(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	a.Feed(newTestEvent(42, 99, 0xDEAD, DirSend, []byte("data")))
	a.FlushAll()

	events := drainOutput(a.Output)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].SSLPTR != 0xDEAD {
		t.Errorf("expected SSLPTR 0xDEAD, got 0x%x", events[0].SSLPTR)
	}
	if events[0].HTTP != nil {
		t.Error("expected HTTP to be nil for non-HTTP data")
	}
}

func TestAssembler_HTTPParsing(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	httpReq := []byte("GET /path HTTP/1.1\r\nHost: test.com\r\n\r\n")
	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, httpReq))
	a.FlushAll()

	events := drainOutput(a.Output)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].HTTP == nil {
		t.Fatal("expected HTTP to be parsed")
	}
	if events[0].HTTP.Method != "GET" {
		t.Errorf("expected method GET, got %s", events[0].HTTP.Method)
	}
}

func TestAssembler_DifferentPIDs(t *testing.T) {
	a := NewAssembler()
	defer close(a.Output)

	// Same TID, SSLPTR but different PIDs = different streams
	a.Feed(newTestEvent(1, 100, 0x1000, DirSend, []byte("pid1")))
	a.Feed(newTestEvent(2, 100, 0x1000, DirSend, []byte("pid2")))

	a.FlushAll()
	events := drainOutput(a.Output)

	if len(events) != 2 {
		t.Fatalf("expected 2 events (different PIDs), got %d", len(events))
	}
}

func TestAssembler_TimeoutFlush(t *testing.T) {
	a := NewAssemblerWithTimeout(50 * time.Millisecond)
	defer func() {
		close(a.stopCh)
		a.flushTicker.Stop()
		close(a.Output)
	}()

	a.Feed(newTestEvent(1, 1, 0x1000, DirSend, []byte("slow data")))

	// No output yet (buffer is still open)
	events := drainOutput(a.Output)
	if len(events) != 0 {
		t.Fatal("expected no output before timeout")
	}

	// Wait for the timeout flush to trigger
	time.Sleep(200 * time.Millisecond)

	events = drainOutput(a.Output)
	if len(events) != 1 {
		t.Fatalf("expected 1 event after timeout flush, got %d", len(events))
	}
	if string(events[0].Data) != "slow data" {
		t.Errorf("expected 'slow data', got '%s'", string(events[0].Data))
	}
}
