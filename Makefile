.PHONY: all generate build clean

all: generate build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

generate: vmlinux.h
	go generate ./...

build: generate
	go build -o konami

clean:
	rm -f konami vmlinux.h konami_bpfeb.go konami_bpfeb.o konami_bpfel.go konami_bpfel.o
