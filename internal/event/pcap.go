package event

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"sync"
	"time"
)

const pcapBufSize = 64 * 1024   // 64KB write buffer
const maxPacketBufSize = 65535 // snapLen

// PCAP constants
const (
	pcapMagic       = 0xa1b2c3d4
	pcapVersionMaj  = 2
	pcapVersionMin  = 4
	linkTypeRaw     = 101 // LINKTYPE_RAW — raw IPv4
	snapLen         = 65535
	clientPort      = uint16(54321)
	serverPort      = uint16(443)
)

// streamSeqKey identifies a TCP stream + direction for sequence number tracking.
type streamSeqKey struct {
	srcIP, dstIP uint32
	srcPort      uint16
	dstPort      uint16
}

// PcapConnInfo holds real TCP connection info for PCAP output.
type PcapConnInfo struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// ConnLookup is a function that returns connection info for a given PID and SSL pointer.
// The returned PcapConnInfo should have addresses oriented as client→server.
type ConnLookup func(pid uint32, sslPtr uint64) (PcapConnInfo, bool)

// PCAPWriter writes assembled TLS events as pseudo-TCP packets to a pcap file.
type PCAPWriter struct {
	mu        sync.Mutex
	w         io.Writer
	file      *os.File
	seqs      map[streamSeqKey]uint32
	ipCache   map[uint32]uint32 // PID -> pseudo IP
	connFn    ConnLookup        // optional: real connection info
	packetBuf sync.Pool         // reusable packet buffers
}

// NewPCAPWriter creates a pcap file and writes the global header.
func NewPCAPWriter(path string) (*PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create pcap file: %w", err)
	}

	bw := bufio.NewWriterSize(f, pcapBufSize)

	pw := &PCAPWriter{
		w:       bw,
		file:    f,
		seqs:    make(map[streamSeqKey]uint32),
		ipCache: make(map[uint32]uint32),
		packetBuf: sync.Pool{
			New: func() any {
				buf := make([]byte, maxPacketBufSize)
				return &buf
			},
		},
	}

	if err := pw.writeGlobalHeader(); err != nil {
		f.Close()
		return nil, err
	}
	return pw, nil
}

func (pw *PCAPWriter) writeGlobalHeader() error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMin)
	// hdr[8:12] = thiszone (0)
	// hdr[12:16] = sigfigs (0)
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkTypeRaw)
	_, err := pw.w.Write(hdr[:])
	return err
}

// Write writes a single assembled TLS event as a pseudo TCP packet.
func (pw *PCAPWriter) Write(ev *AssembledEvent) {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	srcIP, dstIP, srcPort, dstPort := pw.streamAddrs(ev)
	payload := ev.Data
	ts := ev.Timestamp

	// Build IP + TCP header + payload using pooled buffer
	bufPtr := pw.packetBuf.Get().(*[]byte)
	packet := pw.buildPacket(*bufPtr, srcIP, dstIP, srcPort, dstPort, payload, ts)

	// Update sequence number
	key := streamSeqKey{srcIP, dstIP, srcPort, dstPort}
	pw.seqs[key] += uint32(len(payload))

	// Write pcap packet record
	pw.writePacketRecord(ts, packet)

	// Return buffer to pool
	pw.packetBuf.Put(bufPtr)
}

// Close flushes the buffer and closes the pcap file.
func (pw *PCAPWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if bw, ok := pw.w.(*bufio.Writer); ok {
		bw.Flush()
	}
	if pw.file != nil {
		return pw.file.Close()
	}
	return nil
}

// SetConnLookup sets a connection lookup function for resolving real IP:port info.
func (pw *PCAPWriter) SetConnLookup(fn ConnLookup) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.connFn = fn
}

// streamAddrs returns IP addresses and ports based on event direction.
// Uses real connection info from lookup function if available, otherwise falls back to pseudo IPs.
func (pw *PCAPWriter) streamAddrs(ev *AssembledEvent) (srcIP, dstIP uint32, srcPort, dstPort uint16) {
	// Try real connection info first
	if pw.connFn != nil {
		if info, ok := pw.connFn(ev.PID, ev.SSLPTR); ok {
			if ev.Direction == DirSend {
				return info.SrcIP, info.DstIP, info.SrcPort, info.DstPort
			}
			return info.DstIP, info.SrcIP, info.DstPort, info.SrcPort
		}
	}

	// Fallback to pseudo IPs
	pidIP := pw.pseudoIP(ev.PID)
	serverIP := uint32(0x0A000001) // 10.0.0.1

	if ev.Direction == DirSend {
		return pidIP, serverIP, clientPort, serverPort
	}
	return serverIP, pidIP, serverPort, clientPort
}

// pseudoIP generates a stable pseudo IP from PID: 10.0.X.Y
func (pw *PCAPWriter) pseudoIP(pid uint32) uint32 {
	if ip, ok := pw.ipCache[pid]; ok {
		return ip
	}
	h := fnv.New32a()
	binary.Write(h, binary.LittleEndian, pid)
	hash := h.Sum32()
	ip := (10 << 24) | (uint32(byte(hash>>16))<<16) | (uint32(byte(hash>>8))<<8) | uint32(byte(hash))
	if ip == 0x0A000001 {
		ip = 0x0A000002 // avoid collision with server
	}
	pw.ipCache[pid] = ip
	return ip
}

func (pw *PCAPWriter) buildPacket(prealloc []byte, srcIP, dstIP uint32, srcPort, dstPort uint16, payload []byte, ts time.Time) []byte {
	ipHdrLen := 20
	tcpHdrLen := 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)

	buf := prealloc[:totalLen]

	// IPv4 header
	buf[0] = 0x45                                // version 4, IHL 5
	buf[1] = 0x00                                // DSCP
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	// buf[4:6] = identification (0)
	// buf[6:8] = flags/fragment (0)
	buf[8] = 64                                  // TTL
	buf[9] = 6                                   // protocol: TCP
	binary.BigEndian.PutUint32(buf[12:16], srcIP)
	binary.BigEndian.PutUint32(buf[16:20], dstIP)
	// IP checksum
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHdrLen]))

	// TCP header
	tcpOff := ipHdrLen
	binary.BigEndian.PutUint16(buf[tcpOff:tcpOff+2], srcPort)
	binary.BigEndian.PutUint16(buf[tcpOff+2:tcpOff+4], dstPort)
	key := streamSeqKey{srcIP, dstIP, srcPort, dstPort}
	seq := pw.seqs[key]
	binary.BigEndian.PutUint32(buf[tcpOff+4:tcpOff+8], seq)
	binary.BigEndian.PutUint32(buf[tcpOff+8:tcpOff+12], 0) // ack seq
	buf[tcpOff+12] = 0x50                                     // data offset 5 (20 bytes)
	buf[tcpOff+13] = 0x18                                     // flags: PSH + ACK
	binary.BigEndian.PutUint16(buf[tcpOff+14:tcpOff+16], 0xFFFF) // window
	// TCP checksum (set to 0 — optional for pcap analysis)
	// buf[tcpOff+16:tcpOff+18] = 0 (zero already)
	// Urgent pointer = 0

	// Payload
	copy(buf[ipHdrLen+tcpHdrLen:], payload)

	// Compute TCP checksum with pseudo header
	tcpChecksum := tcpPseudoChecksum(buf[tcpOff:], srcIP, dstIP, uint16(tcpHdrLen+len(payload)))
	binary.BigEndian.PutUint16(buf[tcpOff+16:tcpOff+18], tcpChecksum)

	return buf
}

func (pw *PCAPWriter) writePacketRecord(ts time.Time, packet []byte) {
	epoch := ts.Unix()
	usec := ts.Nanosecond() / 1000

	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(epoch))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(usec))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(packet)))
	pw.w.Write(hdr[:])
	pw.w.Write(packet)
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpPseudoChecksum(tcpHdr []byte, srcIP, dstIP uint32, length uint16) uint16 {
	var sum uint32
	sum += srcIP >> 16
	sum += srcIP & 0xFFFF
	sum += dstIP >> 16
	sum += dstIP & 0xFFFF
	sum += 6 // TCP protocol
	sum += uint32(length)

	for i := 0; i < len(tcpHdr)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpHdr[i : i+2]))
	}
	if len(tcpHdr)%2 != 0 {
		sum += uint32(tcpHdr[len(tcpHdr)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
