package main

//go:generate /home/leigh/go/bin/bpf2go -cc clang konami bpf/konami.bpf.c -- -I. -D__TARGET_ARCH_x86
