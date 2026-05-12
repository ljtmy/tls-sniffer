package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"uprobe-tls-sniffer/internal/event"
	"uprobe-tls-sniffer/internal/loader"
	"uprobe-tls-sniffer/internal/resolver"
)

func main() {
	pidFlag := flag.Int("pid", 0, "target process PID (for symbol resolution)")
	pidsFlag := flag.String("pids", "", "comma-separated PIDs to filter (e.g., 1234,5678). If empty, captures all.")
	commFlag := flag.String("comm", "", "process name to filter (matched against /proc/pid/comm)")
	bpfPath := flag.String("bpf", "bpf/sniffer.bpf.o", "path to compiled BPF object file")
	outputFlag := flag.String("output", "text", "output format: text, pcap, or json")
	pcapFileFlag := flag.String("pcap-file", "output.pcap", "pcap output file path (used with --output pcap)")
	ringbufSizeFlag := flag.Int("ringbuf-size", 0, "ring buffer size in bytes (0 = default 256KB, e.g. 524288 for 512KB)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sniffer --pid <PID> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Sniff SSL/TLS plaintext via eBPF uprobe.\n\n")
		fmt.Fprintf(os.Stderr, "Phase 2 features: bidirectional capture, PID/comm filtering,\n")
		fmt.Fprintf(os.Stderr, "OpenSSL 3.x compatibility, partial read assembly.\n")
		fmt.Fprintf(os.Stderr, "Phase 3.1: PCAP file output.\n")
	fmt.Fprintf(os.Stderr, "Phase 3.2: JSON output, HTTP parsing, multi-library, connection tracking.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *outputFlag != "text" && *outputFlag != "pcap" && *outputFlag != "json" {
		fmt.Fprintf(os.Stderr, "error: --output must be 'text', 'pcap', or 'json'\n")
		os.Exit(1)
	}

	if *pidFlag == 0 {
		if flag.NArg() > 0 {
			p, err := strconv.Atoi(flag.Arg(0))
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid PID: %s\n", flag.Arg(0))
				os.Exit(1)
			}
			*pidFlag = p
		} else {
			fmt.Fprintf(os.Stderr, "error: --pid is required for symbol resolution\n\n")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Resolve all TLS libraries and symbols
	libs, err := resolver.ResolveAllLibs(*pidFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving TLS libraries: %v\n", err)
		os.Exit(1)
	}
	for _, lib := range libs {
		fmt.Printf("[*] Found %s (%s)\n", lib.Path, lib.Type)
		for name, off := range lib.Offsets {
			fmt.Printf("    %s @ 0x%x\n", name, off)
		}
	}

	// Load BPF program
	ldr, err := loader.New(*bpfPath, &loader.Options{
		RingBufSize: uint32(*ringbufSizeFlag),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading BPF: %v\n", err)
		os.Exit(1)
	}
	defer ldr.Close()

	// Set PID filter if specified
	var filterPIDs []int
	if *pidsFlag != "" {
		for _, s := range strings.Split(*pidsFlag, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := strconv.Atoi(s)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid PID in --pids: %s\n", s)
				os.Exit(1)
			}
			filterPIDs = append(filterPIDs, p)
		}
	} else if *commFlag != "" {
		// Find PIDs by process name
		filterPIDs, err = findPIDsByComm(*commFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error finding PIDs for comm '%s': %v\n", *commFlag, err)
			os.Exit(1)
		}
		if len(filterPIDs) == 0 {
			fmt.Fprintf(os.Stderr, "no processes found with name '%s'\n", *commFlag)
			os.Exit(1)
		}
	}

	if len(filterPIDs) > 0 {
		if err := ldr.SetPIDFilter(filterPIDs); err != nil {
			fmt.Fprintf(os.Stderr, "error setting PID filter: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] PID filter: %v\n", filterPIDs)
	}

	// Attach all available probes across all discovered libraries
	if err := ldr.AttachAllLibs(libs); err != nil {
		fmt.Fprintf(os.Stderr, "error attaching probes: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Attached probes to %d library(ies)\n", len(libs))

	// Create connection tracker for SSL→fd mapping
	connTracker := resolver.NewConnTracker()

	// Start reading events
	rbMap, err := ldr.GetRingBufMap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting ringbuf map: %v\n", err)
		os.Exit(1)
	}

	dataChan := make(chan *event.TLSEvent, 64)
	if err := ldr.StartReadingWithTracker(rbMap, dataChan, connTracker); err != nil {
		fmt.Fprintf(os.Stderr, "error starting reader: %v\n", err)
		os.Exit(1)
	}

	// Start assembler for partial read handling
	assembler := event.NewAssembler()

	// Feed raw events into assembler
	go func() {
		for ev := range dataChan {
			assembler.Feed(ev)
		}
		assembler.FlushAll()
		close(assembler.Output)
	}()

	fmt.Println("[*] Listening for TLS events... Press Ctrl+C to stop.")

	// Create writer based on output format
	type eventWriter interface {
		Write(ev *event.AssembledEvent)
		Close() error
	}

	var writer eventWriter
	switch *outputFlag {
	case "pcap":
		pw, err := event.NewPCAPWriter(*pcapFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating pcap writer: %v\n", err)
			os.Exit(1)
		}
		pw.SetConnLookup(func(pid uint32, sslPtr uint64) (event.PcapConnInfo, bool) {
			info, ok := connTracker.Lookup(pid, sslPtr)
			if !ok {
				return event.PcapConnInfo{}, false
			}
			return event.PcapConnInfo{
				SrcIP:   ipToUint32(info.LocalIP),
				DstIP:   ipToUint32(info.RemoteIP),
				SrcPort: info.LocalPort,
				DstPort: info.RemotePort,
			}, true
		})
		writer = pw
		defer pw.Close()
		fmt.Printf("[*] Writing pcap to %s\n", *pcapFileFlag)
	case "json":
		writer = event.NewJSONWriter()
	default:
		writer = event.NewStdoutWriter()
	}

	// Handle signals: close loader to trigger clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt, shutting down...")
		ldr.Close()
	}()

	// Output assembled events
	for assembled := range assembler.Output {
		writer.Write(assembled)
	}
}

// findPIDsByComm scans /proc to find PIDs matching a process name.
func findPIDsByComm(comm string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == comm {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}
