package resolver

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxConnTrackEntries = 4096

// ConnInfo holds the 4-tuple for a TLS connection.
type ConnInfo struct {
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
	lastSeen   time.Time
}

// ConnKey uniquely identifies a TLS stream.
type ConnKey struct {
	PID    uint32
	SSLPTR uint64
}

// ConnTracker maps SSL pointers to real TCP connection info.
type ConnTracker struct {
	mu    sync.RWMutex
	conns map[ConnKey]ConnInfo
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		conns: make(map[ConnKey]ConnInfo),
	}
}

// Track records an ssl_ptr → fd mapping and resolves the connection info from /proc.
func (ct *ConnTracker) Track(pid uint32, sslPtr uint64, fd uint32) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	key := ConnKey{PID: pid, SSLPTR: sslPtr}

	info, err := resolveConnInfo(pid, fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "conntrack: resolve pid=%d ssl=0x%x fd=%d failed: %v\n", pid, sslPtr, fd, err)
		return
	}
	info.lastSeen = time.Now()
	ct.conns[key] = info

	// Evict stale entries if map is too large
	if len(ct.conns) > maxConnTrackEntries {
		ct.evictStale()
	}
}

// Lookup returns connection info for an SSL stream, if available.
func (ct *ConnTracker) Lookup(pid uint32, sslPtr uint64) (ConnInfo, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	info, ok := ct.conns[ConnKey{PID: pid, SSLPTR: sslPtr}]
	return info, ok
}

// evictStale removes the oldest half of entries. Must be called with ct.mu held.
func (ct *ConnTracker) evictStale() {
	type kv struct {
		key  ConnKey
		info ConnInfo
	}
	all := make([]kv, 0, len(ct.conns))
	for k, v := range ct.conns {
		all = append(all, kv{k, v})
	}
	// Sort by lastSeen ascending (oldest first)
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].info.lastSeen.Before(all[i].info.lastSeen) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	// Remove oldest half
	removeCount := len(all) / 2
	for i := 0; i < removeCount; i++ {
		delete(ct.conns, all[i].key)
	}
}

// resolveConnInfo reads /proc to find the TCP 4-tuple for a given PID and fd.
func resolveConnInfo(pid uint32, fd uint32) (ConnInfo, error) {
	// Step 1: Get socket inode from /proc/<pid>/fd/<fd>
	fdLink := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(fdLink)
	if err != nil {
		return ConnInfo{}, fmt.Errorf("readlink %s: %w", fdLink, err)
	}
	if !strings.HasPrefix(target, "socket:[") {
		return ConnInfo{}, fmt.Errorf("fd %d is not a socket: %s", fd, target)
	}
	// Extract inode: "socket:[12345]"
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")

	// Step 2: Find matching entry in /proc/<pid>/net/tcp or tcp6
	info, err := lookupTCPConn(pid, inode)
	if err != nil {
		// Try tcp6
		info, err = lookupTCP6Conn(pid, inode)
	}
	return info, err
}

// lookupTCPConn parses /proc/<pid>/net/tcp for a matching inode.
func lookupTCPConn(pid uint32, inode string) (ConnInfo, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		return ConnInfo{}, err
	}

	for _, line := range strings.Split(string(data), "\n")[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[9] != inode {
			continue
		}
		// fields[1] = local_address (hex IP:port)
		// fields[2] = remote_address (hex IP:port)
		localIP, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}
		return ConnInfo{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}, nil
	}
	return ConnInfo{}, fmt.Errorf("inode %s not found in /proc/%d/net/tcp", inode, pid)
}

// lookupTCP6Conn parses /proc/<pid>/net/tcp6 for a matching inode.
func lookupTCP6Conn(pid uint32, inode string) (ConnInfo, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp6", pid))
	if err != nil {
		return ConnInfo{}, err
	}

	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[9] != inode {
			continue
		}
		localIP, localPort, err := parseHexAddr6(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexAddr6(fields[2])
		if err != nil {
			continue
		}
		return ConnInfo{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}, nil
	}
	return ConnInfo{}, fmt.Errorf("inode %s not found in /proc/%d/net/tcp6", inode, pid)
}

// parseHexAddr parses "AABBCCDD:PORT" (hex IP in little-endian uint32 + hex port).
func parseHexAddr(s string) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr: %s", s)
	}
	ipHex := parts[0]
	portHex := parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil || len(ipBytes) != 4 {
		return nil, 0, fmt.Errorf("invalid IP hex: %s", ipHex)
	}
	// Kernel stores IP in little-endian (host byte order for IPv4)
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port hex: %s", portHex)
	}
	return ip, uint16(port), nil
}

// parseHexAddr6 parses "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PORT" (32 hex chars = 128-bit IPv6).
func parseHexAddr6(s string) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr6: %s", s)
	}
	ipHex := parts[0]
	portHex := parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil || len(ipBytes) != 16 {
		return nil, 0, fmt.Errorf("invalid IPv6 hex: %s", ipHex)
	}

	// Kernel stores IPv6 as 4 little-endian uint32 words
	var ip [16]byte
	for i := 0; i < 4; i++ {
		word := binary.LittleEndian.Uint32(ipBytes[i*4 : i*4+4])
		binary.BigEndian.PutUint32(ip[i*4:i*4+4], word)
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port hex: %s", portHex)
	}
	return net.IP(ip[:]), uint16(port), nil
}
