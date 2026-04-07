# Port Scanner in C

A compact, educational TCP connect-based port scanner written in C. Scans a range of ports on a target host using non-blocking sockets and reports which ports are open, along with their well-known service names.

## Features

- Non-blocking TCP connect with configurable timeout (`select`-based)
- Hostname resolution via `getaddrinfo`
- Dynamic result array using `calloc` + `realloc`
- Well-known service name lookup (FTP, SSH, HTTP, HTTPS, MySQL, etc.)
- Verbose mode to print every port scanned, not just open ones
- Clean memory management — no leaks

## Build

> **Requires:** GCC and a POSIX-compatible system (Linux / macOS)

```bash
make
```

This compiles `portscanner.c` with `-Wall -Wextra -pedantic -std=c11 -g` and produces the `portscanner` binary.

To clean up:

```bash
make clean
```

## Usage

```
./portscanner <host> [start] [end] [-v] [-t timeout_ms]
```

| Argument       | Description                                     | Default |
|----------------|-------------------------------------------------|---------|
| `host`         | Target hostname or IP address                   | *(required)* |
| `start`        | First port in the scan range                    | `1`     |
| `end`          | Last port in the scan range                     | `1024`  |
| `-v`           | Verbose mode — print every port, not just open  | off     |
| `-t <ms>`      | TCP connect timeout in milliseconds             | `500`   |

### Examples

Scan the default range (ports 1–1024) on `scanme.nmap.org`:
```bash
./portscanner scanme.nmap.org
```

Scan ports 20–443 with a 200 ms timeout:
```bash
./portscanner 192.168.1.1 20 443 -t 200
```

Scan ports 1–100 with verbose output:
```bash
./portscanner localhost 1 100 -v
```

### Sample Output

```
Scanning scanme.nmap.org ports 1-1024 (timeout 500 ms) ...

PORT       STATE      SERVICE
────       ─────      ───────
22         open       SSH
80         open       HTTP

Done. 2 result(s) recorded.
```

## Project Structure

```
portscanner/
├── portscanner.c   # Scanner implementation + main()
├── portscanner.h   # Public API, structs, and extern declarations
└── Makefile        # Build rules
```

## C Concepts Demonstrated

This project was written to showcase several core C language features:

| Concept | Where used |
|---------|-----------|
| **Global variables** | `g_timeout_ms`, `g_verbose`, `g_target_host` |
| **`extern`** | Globals defined in `portscanner.c`, declared `extern` in `portscanner.h` |
| **`static`** | `resolve_host()`, `try_connect()`, and `SERVICE_TABLE` are file-private |
| **`calloc`** | Initial zeroed allocation of the result array |
| **`realloc`** | Doubles array capacity when results overflow |
| **`malloc` / `strdup`** | Heap-duplicates service name strings into each result |
| **`argc` / `argv`** | Full CLI flag parsing in `main()` |
| **Non-blocking I/O** | `fcntl(O_NONBLOCK)` + `select()` for timeout-aware connect |
| **Include guards** | `#ifndef PORTSCANNER_H` in the header |

## License

This project is released into the public domain for educational use.
