 // portscanner.h — Public API for the port scanner.

#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <stddef.h>

/* ── Result record stored for each scanned port ─────────────────────────── */
typedef struct {
    int    port;        /* Port number that was probed      */
    int    open;        /* 1 = open/accepting, 0 = closed   */
    char  *service;     /* Well-known service name or NULL  */
} PortResult;

/* ── Global scanner state (defined in portscanner.c, extern here) ─────── */
extern int           g_timeout_ms;   /* Connect timeout in milliseconds      */
extern int           g_verbose;      /* Print every port, not just open ones */
extern const char   *g_target_host;  /* Host being scanned (set from argv)   */

/* ── Public functions ────────────────────────────────────────────────────── */

/**
 * scan_range – Scan ports [start, end] on g_target_host.
 *
 * Allocates a PortResult array on the heap (calloc + realloc as needed).
 * Caller must free() the returned pointer.
 *
 * @param start   First port to scan (inclusive).
 * @param end     Last port to scan  (inclusive).
 * @param count   Output: number of results stored in the returned array.
 * @return        Heap-allocated PortResult array, or NULL on failure.
 */
PortResult *scan_range(int start, int end, size_t *count);

/**
 * print_results – Pretty-print the result array to stdout.
 *
 * @param results  Array returned by scan_range().
 * @param count    Number of elements in the array.
 */
void print_results(const PortResult *results, size_t count);

/**
 * lookup_service – Return the well-known name for a port, or NULL.
 *
 * Uses a static internal table; no heap allocation.
 *
 * @param port  Port number to look up.
 * @return      String literal, or NULL if unknown.
 */
const char *lookup_service(int port);

#endif /* PORTSCANNER_H */
