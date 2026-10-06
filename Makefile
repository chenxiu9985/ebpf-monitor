SHELL := /bin/bash
CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
CFLAGS := -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibuild -Ibpf
LIBS := $(shell pkg-config --libs libbpf) -lelf -lz

.PHONY: all test doctor clean
all: build/collector
build:
	mkdir -p build
build/vmlinux.h: | build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@
build/monitor.bpf.o: bpf/monitor.bpf.c bpf/events.h build/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
build/monitor.skel.h: build/monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@
build/collector: collector/main.c collector/transport.h collector/control.h collector/registry.h bpf/events.h build/monitor.skel.h
	$(CC) $(CFLAGS) -Ibuild -Ibpf $(shell pkg-config --cflags libbpf) $< -o $@ $(LIBS)
test:
	python3 -m unittest discover -s tests -v
doctor:
	python3 -m monitor doctor
clean:
	rm -f build/collector build/monitor.bpf.o build/monitor.skel.h build/vmlinux.h
