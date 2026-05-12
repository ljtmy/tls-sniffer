package resolver

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LibType identifies the TLS library family.
type LibType int

const (
	LibOpenSSL LibType = iota // includes BoringSSL (same API)
	LibGnuTLS
)

func (lt LibType) String() string {
	switch lt {
	case LibOpenSSL:
		return "OpenSSL"
	case LibGnuTLS:
		return "GnuTLS"
	default:
		return "unknown"
	}
}

// LibInfo describes a discovered TLS library.
type LibInfo struct {
	Path    string
	Type    LibType
	Offsets map[string]uint64
}

// SymbolResult holds a resolved symbol name and its file offset.
type SymbolResult struct {
	Name       string
	FileOffset uint64
}

// defaultSymbols returns the symbols to probe for each library type.
func defaultSymbols(lt LibType) []string {
	switch lt {
	case LibOpenSSL:
		return []string{"SSL_write", "SSL_write_ex", "SSL_read", "SSL_read_ex", "SSL_set_fd"}
	case LibGnuTLS:
		return []string{"gnutls_record_send", "gnutls_record_recv"}
	default:
		return nil
	}
}

// ResolveAllLibs discovers all TLS libraries for the given PID and resolves
// default symbols for each. Returns a list of LibInfo, one per discovered library.
func ResolveAllLibs(pid int) ([]LibInfo, error) {
	mapsPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "maps")
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mapsPath, err)
	}

	type libCandidate struct {
		path string
		lt   LibType
	}

	var candidates []libCandidate
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "r-xp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := strings.TrimSpace(fields[5])
		base := filepath.Base(path)

		switch {
		case strings.Contains(base, "libssl"):
			candidates = append(candidates, libCandidate{path, LibOpenSSL})
		case strings.Contains(base, "libboringssl"):
			candidates = append(candidates, libCandidate{path, LibOpenSSL})
		case strings.Contains(base, "libgnutls"):
			candidates = append(candidates, libCandidate{path, LibGnuTLS})
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no TLS libraries found in maps for pid %d", pid)
	}

	// Deduplicate by path
	seen := make(map[string]bool)
	var libs []LibInfo
	for _, c := range candidates {
		if seen[c.path] {
			continue
		}
		seen[c.path] = true

		syms := defaultSymbols(c.lt)
		offsets := make(map[string]uint64)
		for _, sym := range syms {
			off, err := resolveSymbolOffset(c.path, sym)
			if err == nil {
				offsets[sym] = off
			}
		}
		if len(offsets) == 0 {
			continue
		}
		libs = append(libs, LibInfo{
			Path:    c.path,
			Type:    c.lt,
			Offsets: offsets,
		})
	}

	if len(libs) == 0 {
		return nil, fmt.Errorf("no TLS symbols resolved for pid %d", pid)
	}

	return libs, nil
}

// resolveSymbolOffset reads the ELF symbol table and returns the file offset
// of the given symbol name.
func resolveSymbolOffset(libPath, symbolName string) (uint64, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return 0, fmt.Errorf("open elf %s: %w", libPath, err)
	}
	defer f.Close()

	// Try regular symbols first (may not exist in stripped .so)
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Name == symbolName {
				return virtualAddrToOffset(f, sym.Value)
			}
		}
	}

	// Try dynamic symbols (present in stripped shared libraries)
	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("read dynamic symbols: %w", err)
	}

	for _, sym := range dynSyms {
		if sym.Name == symbolName {
			return virtualAddrToOffset(f, sym.Value)
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbolName, libPath)
}

// virtualAddrToOffset converts a virtual address to a file offset
// by finding the containing PT_LOAD segment.
func virtualAddrToOffset(f *elf.File, vaddr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= prog.Vaddr && vaddr < prog.Vaddr+prog.Memsz {
			return vaddr - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("virtual address 0x%x not in any PT_LOAD segment", vaddr)
}
