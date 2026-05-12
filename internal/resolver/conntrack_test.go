package resolver

import (
	"net"
	"os"
	"testing"
)

func TestConnTracker_TrackAndLookup(t *testing.T) {
	ct := NewConnTracker()

	// Manually insert a connection (bypass /proc lookup)
	ct.mu.Lock()
	ct.conns[ConnKey{PID: 100, SSLPTR: 0xAAAA}] = ConnInfo{
		LocalIP:    net.ParseIP("192.168.1.10"),
		LocalPort:  54321,
		RemoteIP:   net.ParseIP("93.184.216.34"),
		RemotePort: 443,
	}
	ct.mu.Unlock()

	info, ok := ct.Lookup(100, 0xAAAA)
	if !ok {
		t.Fatal("expected Lookup to return true")
	}
	if info.LocalPort != 54321 {
		t.Errorf("expected local port 54321, got %d", info.LocalPort)
	}
	if info.RemotePort != 443 {
		t.Errorf("expected remote port 443, got %d", info.RemotePort)
	}
	if info.LocalIP.String() != "192.168.1.10" {
		t.Errorf("expected local IP 192.168.1.10, got %s", info.LocalIP)
	}
}

func TestConnTracker_LookupNotFound(t *testing.T) {
	ct := NewConnTracker()

	_, ok := ct.Lookup(999, 0xBBBB)
	if ok {
		t.Error("expected Lookup to return false for unknown key")
	}
}

func TestConnTracker_MultipleKeys(t *testing.T) {
	ct := NewConnTracker()

	ct.mu.Lock()
	ct.conns[ConnKey{PID: 1, SSLPTR: 0x100}] = ConnInfo{LocalPort: 1111}
	ct.conns[ConnKey{PID: 1, SSLPTR: 0x200}] = ConnInfo{LocalPort: 2222}
	ct.conns[ConnKey{PID: 2, SSLPTR: 0x100}] = ConnInfo{LocalPort: 3333}
	ct.mu.Unlock()

	info1, ok := ct.Lookup(1, 0x100)
	if !ok || info1.LocalPort != 1111 {
		t.Errorf("expected port 1111, got %d (ok=%v)", info1.LocalPort, ok)
	}
	info2, ok := ct.Lookup(1, 0x200)
	if !ok || info2.LocalPort != 2222 {
		t.Errorf("expected port 2222, got %d (ok=%v)", info2.LocalPort, ok)
	}
	info3, ok := ct.Lookup(2, 0x100)
	if !ok || info3.LocalPort != 3333 {
		t.Errorf("expected port 3333, got %d (ok=%v)", info3.LocalPort, ok)
	}
}

func TestParseHexAddr_IPv4(t *testing.T) {
	// 0100007F = 127.0.0.1 in little-endian
	// 0050 = port 80 in hex
	ip, port, err := parseHexAddr("0100007F:0050")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", ip)
	}
	if port != 80 {
		t.Errorf("expected port 80, got %d", port)
	}
}

func TestParseHexAddr_IPv4Public(t *testing.T) {
	// 5ED8B422 = 34.180.216.94 in little-endian
	ip, port, err := parseHexAddr("5ED8B422:01BB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "34.180.216.94" {
		t.Errorf("expected 34.180.216.94, got %s", ip)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestParseHexAddr_Invalid(t *testing.T) {
	_, _, err := parseHexAddr("not_hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}

	_, _, err = parseHexAddr("ZZZZ:0050")
	if err == nil {
		t.Error("expected error for invalid IP hex")
	}
}

func TestParseHexAddr6(t *testing.T) {
	// ::1 (loopback) in kernel's little-endian uint32 words
	// Word0: 00000000, Word1: 00000000, Word2: 00000000, Word3: 01000000
	ip, port, err := parseHexAddr6("00000000000000000000000001000000:01BB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "::1" {
		t.Errorf("expected ::1, got %s", ip)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestConnTracker_TrackWithRealProc(t *testing.T) {
	// Test that Track doesn't panic when looking up a non-existent PID
	ct := NewConnTracker()
	ct.Track(99999999, 0x1234, 99)
	// Should not panic, just not find anything
	_, ok := ct.Lookup(99999999, 0x1234)
	if ok {
		t.Error("expected false for non-existent PID")
	}
}

func TestConnTracker_TrackWithOwnPID(t *testing.T) {
	// Open a real file descriptor (not a socket) and try to track it
	ct := NewConnTracker()
	pid := uint32(os.Getpid())

	// This should fail gracefully since the fd is not a socket
	ct.Track(pid, 0xBEEF, 0) // fd 0 = stdin, not a socket
	_, ok := ct.Lookup(pid, 0xBEEF)
	if ok {
		t.Error("expected false for non-socket fd")
	}
}
