package event

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxDataSize = 4096

const (
	DirSend = 0
	DirRecv = 1
)

const (
	EventData     = 0
	EventConnInfo = 1
)

// TLSEvent mirrors the C struct tls_event from sniffer.h.
type TLSEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	DataLen   uint32
	Direction uint32
	SSLPTR    uint64
	EventType uint32
	FD        uint32
	Comm      [16]byte
	Data      [MaxDataSize]byte
}

// CommString returns the process name as a string.
func (e *TLSEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// DirectionString returns "SEND" or "RECV".
func (e *TLSEvent) DirectionString() string {
	if e.Direction == DirSend {
		return "SEND"
	}
	return "RECV"
}

// AssembledEvent is the final output after partial read reassembly.
type AssembledEvent struct {
	PID       uint32
	TID       uint32
	SSLPTR    uint64
	Comm      string
	Direction uint32
	Timestamp time.Time
	Data      []byte
	HTTP      *ParsedHTTP // non-nil if data parses as HTTP
}

func (e *AssembledEvent) DirectionString() string {
	if e.Direction == DirSend {
		return "SEND"
	}
	return "RECV"
}

// StreamKey uniquely identifies a TLS stream for partial read assembly.
type StreamKey struct {
	PID    uint32
	TID    uint32
	SSLPTR uint64
}

// Assembler buffers partial reads and emits assembled events.
type Assembler struct {
	mu       sync.Mutex
	bufs     map[StreamKey]*partialBuffer
	Output   chan *AssembledEvent
	bootTime time.Time
	pool     sync.Pool
}

type partialBuffer struct {
	comm      string
	direction uint32
	timestamp uint64 // first chunk ktime_ns
	data      []byte
}

const partialBufInitialCap = 4096

func NewAssembler() *Assembler {
	a := &Assembler{
		bufs:     make(map[StreamKey]*partialBuffer),
		Output:   make(chan *AssembledEvent, 64),
		bootTime: computeBootTime(),
	}
	a.pool = sync.Pool{
		New: func() any {
			return &partialBuffer{
				data: make([]byte, 0, partialBufInitialCap),
			}
		},
	}
	return a
}

func (a *Assembler) getBuffer() *partialBuffer {
	return a.pool.Get().(*partialBuffer)
}

func (a *Assembler) putBuffer(buf *partialBuffer) {
	buf.comm = ""
	buf.direction = 0
	buf.timestamp = 0
	buf.data = buf.data[:0]
	a.pool.Put(buf)
}

// computeBootTime reads /proc/uptime to determine the system boot time.
// bpf_ktime_get_ns() returns nanoseconds since boot, so:
//   wall_time = boot_time + ktime_ns
func computeBootTime() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return time.Time{}
	}
	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(uptimeSec * float64(time.Second)))
}

func (a *Assembler) Feed(ev *TLSEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := StreamKey{PID: ev.PID, TID: ev.TID, SSLPTR: ev.SSLPTR}
	existing, ok := a.bufs[key]

	if ok && existing.direction == ev.Direction {
		existing.data = append(existing.data, ev.Data[:ev.DataLen]...)
		return
	}

	if ok {
		a.flush(key, existing)
	}

	buf := a.getBuffer()
	buf.comm = ev.CommString()
	buf.direction = ev.Direction
	buf.timestamp = ev.Timestamp
	buf.data = append(buf.data, ev.Data[:ev.DataLen]...)
	a.bufs[key] = buf
}

// FlushAll flushes all remaining buffers.
func (a *Assembler) FlushAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, buf := range a.bufs {
		a.flush(key, buf)
	}
}

func (a *Assembler) flush(key StreamKey, buf *partialBuffer) {
	delete(a.bufs, key)
	if len(buf.data) == 0 {
		a.putBuffer(buf)
		return
	}
	ev := &AssembledEvent{
		PID:       key.PID,
		TID:       key.TID,
		SSLPTR:    key.SSLPTR,
		Comm:      buf.comm,
		Direction: buf.direction,
		Timestamp: a.ktimeToWall(buf.timestamp),
		Data:      append([]byte(nil), buf.data...),
	}
	ev.HTTP = TryParseHTTP(ev.Data)
	a.putBuffer(buf)
	a.Output <- ev
}

func (a *Assembler) ktimeToWall(ktimeNs uint64) time.Time {
	// bpf_ktime_get_ns() returns nanoseconds since boot.
	// wall_time = boot_time + ktime_ns
	if a.bootTime.IsZero() {
		return time.Now()
	}
	return time.Unix(0, a.bootTime.UnixNano()+int64(ktimeNs))
}
