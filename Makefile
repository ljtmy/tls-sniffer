CLANG ?= clang
GO ?= go
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := bpf/sniffer.bpf.c
BPF_OBJ := bpf/sniffer.bpf.o
BPF_HEADERS := bpf/sniffer.h
VMLINUX_H := bpf/vmlinux.h

.PHONY: all clean build bpf vmlinux

all: bpf build

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS) $(VMLINUX_H)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

build:
	CGO_ENABLED=0 $(GO) build -o bin/sniffer ./cmd/sniffer/

clean:
	rm -f $(BPF_OBJ) bin/sniffer
