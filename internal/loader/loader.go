package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"uprobe-tls-sniffer/internal/event"
	"uprobe-tls-sniffer/internal/resolver"
)

// probeAttachment holds a named link for cleanup.
type probeAttachment struct {
	name string
	link link.Link
}

// Loader manages BPF program loading, uprobe/uretprobe attachment, and event consumption.
type Loader struct {
	collection *ebpf.Collection
	probes     []probeAttachment
	reader     *ringbuf.Reader
	eventChan  chan *event.TLSEvent
}

// Options configures the BPF loader.
type Options struct {
	RingBufSize uint32 // ring buffer size in bytes, 0 = default 256KB
}

// New loads the BPF object file and returns a Loader ready for attaching.
func New(bpfObjPath string, opts *Options) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	// Override ring buffer size if specified
	if opts != nil && opts.RingBufSize > 0 {
		if m, ok := spec.Maps["events"]; ok {
			m.MaxEntries = opts.RingBufSize
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	return &Loader{
		collection: coll,
		eventChan:  make(chan *event.TLSEvent, 64),
	}, nil
}

// SetPIDFilter sets the PID filter map. Only PIDs in the list will generate events.
func (l *Loader) SetPIDFilter(pids []int) error {
	m, ok := l.collection.Maps["pid_filter"]
	if !ok {
		return errors.New("map 'pid_filter' not found in collection")
	}

	one := uint8(1)
	for _, pid := range pids {
		key := uint32(pid)
		if err := m.Put(key, one); err != nil {
			return fmt.Errorf("put pid %d to filter: %w", pid, err)
		}
	}

	// Enable filtering in BPF
	fm, ok := l.collection.Maps["filter_enabled"]
	if !ok {
		return errors.New("map 'filter_enabled' not found in collection")
	}
	return fm.Put(uint32(0), one)
}

// AttachProbe attaches a BPF program to a symbol at the given offset.
// progName is the BPF program section name (e.g., "uprobe_ssl_write").
// libPath is the path to the shared library.
// offset is the file offset of the symbol.
// isUretprobe specifies whether this is a return probe.
func (l *Loader) AttachProbe(progName, libPath string, offset uint64, isUretprobe bool) error {
	prog, ok := l.collection.Programs[progName]
	if !ok {
		return fmt.Errorf("program %s not found in collection", progName)
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", libPath, err)
	}

	var lk link.Link
	if isUretprobe {
		lk, err = ex.Uretprobe("", prog, &link.UprobeOptions{
			Address: offset,
		})
	} else {
		lk, err = ex.Uprobe("", prog, &link.UprobeOptions{
			Address: offset,
		})
	}
	if err != nil {
		return fmt.Errorf("attach %s at 0x%x: %w", progName, offset, err)
	}

	l.probes = append(l.probes, probeAttachment{name: progName, link: lk})
	return nil
}

// AttachAllLibs attaches probes for all discovered TLS libraries.
func (l *Loader) AttachAllLibs(libs []resolver.LibInfo) error {
	for _, lib := range libs {
		if err := l.attachLib(lib); err != nil {
			return fmt.Errorf("attach %s (%s): %w", lib.Path, lib.Type, err)
		}
	}
	if len(l.probes) == 0 {
		return errors.New("no probes attached")
	}
	return nil
}

func (l *Loader) attachLib(lib resolver.LibInfo) error {
	type probeSpec struct {
		symbol    string
		progName  string
		isReturn  bool
	}

	var specs []probeSpec
	switch lib.Type {
	case resolver.LibOpenSSL:
		specs = []probeSpec{
			{"SSL_write", "uprobe_ssl_write", false},
			{"SSL_write_ex", "uprobe_ssl_write_ex", false},
			{"SSL_read", "uprobe_ssl_read", false},
			{"SSL_read", "uretprobe_ssl_read", true},
			{"SSL_read_ex", "uprobe_ssl_read_ex", false},
			{"SSL_read_ex", "uretprobe_ssl_read_ex", true},
			{"SSL_set_fd", "uprobe_ssl_set_fd", false},
		}
	case resolver.LibGnuTLS:
		specs = []probeSpec{
			{"gnutls_record_send", "uprobe_gnutls_send", false},
			{"gnutls_record_recv", "uprobe_gnutls_recv", false},
			{"gnutls_record_recv", "uretprobe_gnutls_recv", true},
		}
	default:
		return fmt.Errorf("unsupported library type: %v", lib.Type)
	}

	for _, s := range specs {
		offset, ok := lib.Offsets[s.symbol]
		if !ok {
			continue
		}
		if err := l.AttachProbe(s.progName, lib.Path, offset, s.isReturn); err != nil {
			return fmt.Errorf("attach %s: %w", s.progName, err)
		}
	}
	return nil
}

// StartReading opens the ring buffer and begins consuming events.
// Events are sent to the returned channel.
func (l *Loader) StartReading() (<-chan *event.TLSEvent, error) {
	rbMap, ok := l.collection.Maps["events"]
	if !ok {
		return nil, errors.New("map 'events' not found in collection")
	}

	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return nil, fmt.Errorf("ringbuf new reader: %w", err)
	}
	l.reader = reader

	go l.readLoop()

	return l.eventChan, nil
}

// GetRingBufMap returns the ring buffer map from the collection.
func (l *Loader) GetRingBufMap() (*ebpf.Map, error) {
	rbMap, ok := l.collection.Maps["events"]
	if !ok {
		return nil, errors.New("map 'events' not found in collection")
	}
	return rbMap, nil
}

// StartReadingWithTracker opens the ring buffer and routes events:
// CONN_INFO events go to tracker, DATA events go to dataChan.
func (l *Loader) StartReadingWithTracker(rbMap *ebpf.Map, dataChan chan<- *event.TLSEvent, tracker ConnTracker) error {
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf new reader: %w", err)
	}
	l.reader = reader

	go l.ReadLoopWithTracker(dataChan, tracker)
	return nil
}

func (l *Loader) readLoop() {
	defer close(l.eventChan)

	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "ringbuf read error: %v\n", err)
			continue
		}

		var ev event.TLSEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "decode event error: %v\n", err)
			continue
		}

		l.eventChan <- &ev
	}
}

// ReadLoopWithTracker reads events and routes CONN_INFO to tracker, DATA to dataChan.
func (l *Loader) ReadLoopWithTracker(dataChan chan<- *event.TLSEvent, tracker ConnTracker) {
	defer close(dataChan)

	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "ringbuf read error: %v\n", err)
			continue
		}

		var ev event.TLSEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "decode event error: %v\n", err)
			continue
		}

		if ev.EventType == event.EventConnInfo {
			tracker.Track(ev.PID, ev.SSLPTR, ev.FD)
			continue
		}

		dataChan <- &ev
	}
}

// ConnTracker is the interface for connection tracking.
type ConnTracker interface {
	Track(pid uint32, sslPtr uint64, fd uint32)
}

// Close cleans up all resources.
func (l *Loader) Close() {
	if l.reader != nil {
		l.reader.Close()
	}
	for _, p := range l.probes {
		p.link.Close()
	}
	if l.collection != nil {
		l.collection.Close()
	}
}

// WaitSignals blocks until SIGINT or SIGTERM is received, then calls Close.
func (l *Loader) WaitSignals() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	fmt.Println("\nReceived interrupt, exiting...")
	l.Close()
}
