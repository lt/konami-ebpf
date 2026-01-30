#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KONAMI_SEQ_LEN 10
const u32 konami_seq[KONAMI_SEQ_LEN] = {103, 103, 108, 108, 105, 106, 105, 106, 48, 30};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} state_map SEC(".maps");

struct event {
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

SEC("kprobe/input_event")
int BPF_KPROBE(handle_input_event, struct input_dev *dev, unsigned int type, unsigned int code, int value) {
    // type == EV_KEY (1), value == 1 (key press)
    if (type != 1 || value != 1) {
        return 0;
    }

    u32 key = 0;
    u32 *pos = bpf_map_lookup_elem(&state_map, &key);
    if (!pos) {
        return 0;
    }

    u32 current_pos = *pos;
    if (current_pos >= KONAMI_SEQ_LEN) {
        current_pos = 0;
    }

    if (code == konami_seq[current_pos]) {
        current_pos++;
    } else {
        current_pos = (code == konami_seq[0]) ? 1 : 0;
    }

    if (current_pos == KONAMI_SEQ_LEN) {
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->ts = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
        current_pos = 0;
    }

    bpf_map_update_elem(&state_map, &key, &current_pos, BPF_ANY);

    return 0;
}
