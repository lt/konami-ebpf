package main

import (
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := konamiObjects{}
	if err := loadKonamiObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("input_event", objs.HandleInputEvent, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %v", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("Waiting for Konami code...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %v", err)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %v", err)
			continue
		}

		if len(record.RawSample) < 8 {
			log.Printf("short sample: %d", len(record.RawSample))
			continue
		}

		ts := binary.LittleEndian.Uint64(record.RawSample)
		log.Printf("Code detected at %d", ts)
	}
}
