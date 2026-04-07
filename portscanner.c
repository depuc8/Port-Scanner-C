/* Feature-test macros must come before any system header */
#define _POSIX_C_SOURCE 200112L   /* getaddrinfo, freeaddrinfo, gai_strerror */
#define _GNU_SOURCE               /* strdup, non-blocking connect extras      */

/**
 * portscanner.c — TCP connect-based port scanner.
 *
 * C language features demonstrated
 * ─────────────────────────────────
 *  global variables  – g_timeout_ms, g_verbose, g_target_host
 *  extern            – declared in portscanner.h, defined here
 *  static            – static helper functions and a static service table
 *  malloc / calloc   – initial result array allocation with calloc()
 *  realloc           – growing the result array when needed
 *  argc / argv       – CLI argument parsing in main()
 *
 * Build:  see Makefile
 * Usage:  ./portscanner <host> [start_port] [end_port] [-v] [-t timeout_ms]
 */

#include "portscanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* POSIX networking */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

/* ── Global variable definitions (extern in portscanner.h) ──────────────── */
int         g_timeout_ms  = 500;   /* Default connect timeout: 500 ms        */
int         g_verbose     = 0;     /* Default: only print open ports          */
const char *g_target_host = NULL;  /* Set by main() from argv                 */

/* ────────────────────────────────────────────────────────────────────────── */
/* Static (file-private) data: well-known port → service name               */
/* ────────────────────────────────────────────────────────────────────────── */
typedef struct { int port; const char *name; } ServiceEntry;

/* static: not visible outside this translation unit */
static const ServiceEntry SERVICE_TABLE[] = {
    {21,   "FTP"},      {22,  "SSH"},      {23,  "Telnet"},
    {25,   "SMTP"},     {53,  "DNS"},      {80,  "HTTP"},
    {110,  "POP3"},     {143, "IMAP"},     {443, "HTTPS"},
    {3306, "MySQL"},    {5432,"PostgreSQL"},{6379,"Redis"},
    {8080, "HTTP-Alt"}, {8443,"HTTPS-Alt"},{27017,"MongoDB"},
    {0, NULL}  /* sentinel */
};

/* ── Static helper: resolve hostname to IPv4 address string ─────────────── */
static int resolve_host(const char *hostname, struct sockaddr_in *addr)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "resolve_host: %s: %s\n", hostname, gai_strerror(rc));
        return -1;
    }
    *addr = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}

/* ── Static helper: attempt a non-blocking TCP connect ─────────────────── */
/**
 * try_connect – Try to TCP-connect to addr:port within g_timeout_ms.
 *
 * Uses non-blocking connect + select() so we don't hang on filtered ports.
 *
 * @return 1 if port is open, 0 if closed/filtered, -1 on error.
 */
static int try_connect(const struct sockaddr_in *base_addr, int port)
{
    struct sockaddr_in addr = *base_addr;
    addr.sin_port = htons((uint16_t)port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set non-blocking so connect returns immediately */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    if (rc == 0) {          /* Instant connect (rare but possible) */
        close(fd);
        return 1;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return 0;
    }

    /* Wait up to g_timeout_ms for the socket to become writable */
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);

    struct timeval tv;
    tv.tv_sec  = g_timeout_ms / 1000;
    tv.tv_usec = (g_timeout_ms % 1000) * 1000;

    int sel = select(fd + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) {         /* Timeout or error → closed/filtered */
        close(fd);
        return 0;
    }

    /* Confirm the connection succeeded (select can return on errors too) */
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    close(fd);
    return (err == 0) ? 1 : 0;
}

/* ── Public: lookup_service ─────────────────────────────────────────────── */
const char *lookup_service(int port)
{
    for (int i = 0; SERVICE_TABLE[i].name != NULL; i++) {
        if (SERVICE_TABLE[i].port == port)
            return SERVICE_TABLE[i].name;
    }
    return NULL;
}

/* ── Public: scan_range ─────────────────────────────────────────────────── */
PortResult *scan_range(int start, int end, size_t *count)
{
    *count = 0;

    struct sockaddr_in addr;
    if (resolve_host(g_target_host, &addr) != 0)
        return NULL;

    /* calloc: allocate zeroed memory for an initial batch of results */
    size_t capacity = 64;
    PortResult *results = calloc(capacity, sizeof(PortResult));
    if (!results) {
        perror("calloc");
        return NULL;
    }

    for (int port = start; port <= end; port++) {
        int open = try_connect(&addr, port);

        if (g_verbose || open == 1) {
            /* Grow the array when we're about to overflow */
            if (*count >= capacity) {
                capacity *= 2;
                /* realloc: resize existing heap block */
                PortResult *tmp = realloc(results, capacity * sizeof(PortResult));
                if (!tmp) {
                    perror("realloc");
                    free(results);
                    return NULL;
                }
                results = tmp;
            }

            results[*count].port    = port;
            results[*count].open    = open;
            /* malloc: duplicate service string so result is self-contained */
            const char *svc = lookup_service(port);
            results[*count].service = svc ? strdup(svc) : NULL;
            (*count)++;
        }

        if (g_verbose) {
            printf("  [%5d] %s\n", port, open ? "OPEN" : "closed");
            fflush(stdout);
        }
    }

    return results;
}

/* ── Public: print_results ──────────────────────────────────────────────── */
void print_results(const PortResult *results, size_t count)
{
    printf("\n%-10s %-10s %s\n", "PORT", "STATE", "SERVICE");
    printf("%-10s %-10s %s\n", "────", "─────", "───────");
    for (size_t i = 0; i < count; i++) {
        if (results[i].open) {
            printf("%-10d %-10s %s\n",
                   results[i].port,
                   "open",
                   results[i].service ? results[i].service : "unknown");
        }
    }
}

/* ── main: argc / argv parsing ──────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* argv[0] = program name, argv[1] = host, optional flags follow */
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <host> [start] [end] [-v] [-t timeout_ms]\n"
            "  host         Target hostname or IP\n"
            "  start        First port (default 1)\n"
            "  end          Last port  (default 1024)\n"
            "  -v           Verbose: print every port\n"
            "  -t <ms>      Connect timeout in ms (default 500)\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    g_target_host = argv[1];
    int start = 1, end = 1024;

    /* Walk remaining argv entries */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[++i]);
            if (g_timeout_ms <= 0) {
                fprintf(stderr, "Invalid timeout: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (i == 2) {
            start = atoi(argv[i]);
        } else if (i == 3) {
            end = atoi(argv[i]);
        }
    }

    if (start < 1 || end > 65535 || start > end) {
        fprintf(stderr, "Invalid port range: %d-%d\n", start, end);
        return EXIT_FAILURE;
    }

    printf("Scanning %s ports %d-%d (timeout %d ms) ...\n",
           g_target_host, start, end, g_timeout_ms);

    size_t count = 0;
    PortResult *results = scan_range(start, end, &count);
    if (!results) {
        fprintf(stderr, "Scan failed.\n");
        return EXIT_FAILURE;
    }

    print_results(results, count);
    printf("\nDone. %zu result(s) recorded.\n", count);

    /* Free each strdup'd service string, then the array itself */
    for (size_t i = 0; i < count; i++)
        free(results[i].service);
    free(results);

    return EXIT_SUCCESS;
}
