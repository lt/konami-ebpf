# konami-ebpf - in-kernel Konami code detector

A small eBPF program that watches keyboard input in the kernel, detects the Konami code (↑ ↑ ↓ ↓ ← → ← → B A), and notifies a userspace Go program.

## Architecture
- A kprobe on `input_event` filters for key presses and maintains a state machine in a BPF map. When the full sequence is matched, it submits an event to a ring buffer.
- A Go program loads the BPF program, attaches it to the kprobe, and listens for events from the ring buffer.

## Usage

1. Build the project:
   ```bash
   make
   ```

2. Run the program:
   ```bash
   sudo ./konami
   ```

3. Type the Konami code on your keyboard: `↑ ↑ ↓ ↓ ← → ← → B A`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
