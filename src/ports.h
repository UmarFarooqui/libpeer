#ifndef PORTS_H_
#define PORTS_H_

#include <stdint.h>
#include <stddef.h>
#include "address.h"

/*
 * Platform Abstraction Layer (PAL) for libpeer.
 *
 * All platform-specific functionality is declared here as extern functions.
 * Each target platform (Linux, RTL8721DM, STM32, etc.) provides its own
 * implementation in a separate file under pal/<platform>/ports_<platform>.c.
 *
 * Core libpeer files must NEVER include platform headers (FreeRTOS.h,
 * task.h, lwip/*.h, etc.) directly — use these functions instead.
 */

/* ---- Timing ---- */

/** Milliseconds since boot (or program start). */
extern uint32_t ports_get_epoch_time(void);

/** Sleep for the given number of milliseconds. */
extern void ports_sleep_ms(int ms);

/* ---- Memory ---- */

/** Return the number of free heap bytes (0 if not available). */
extern uint32_t ports_get_free_heap(void);

/* ---- Network ---- */

/** Resolve a hostname to an Address via DNS. Returns 0 on success, -1 on failure. */
extern int ports_resolve_addr(const char* host, Address* addr);

/** Resolve an mDNS hostname. Returns 0 on success. */
extern int ports_resolve_mdns_host(const char* host, Address* addr);

/** Get the local host IP address. Returns 1 if found, 0 if not. */
extern int ports_get_host_addr(Address* addr, const char* iface_prefix);

/* ---- Entropy ---- */

/**
 * Hardware entropy source for mbedTLS.
 * Signature matches mbedtls_entropy_f_source_t.
 */
extern int ports_hardware_entropy(void* data, unsigned char* output,
                                  size_t len, size_t* olen);

/* ---- DTLS Timer ---- */

/**
 * Opaque DTLS timer context.
 * Each platform defines its internal structure.
 */
typedef struct PortsDtlsTimer PortsDtlsTimer;

/** Allocate a DTLS timer context. */
extern PortsDtlsTimer* ports_dtls_timer_alloc(void);

/** Free a DTLS timer context. */
extern void ports_dtls_timer_free(PortsDtlsTimer* timer);

/**
 * Set DTLS timer delays.
 * Signature matches mbedtls_ssl_set_timer_t set callback.
 *   int_ms: intermediate delay (retransmit trigger)
 *   fin_ms: final delay (timeout)
 * Passing fin_ms=0 cancels the timer.
 */
extern void ports_dtls_timer_set(void* ctx, uint32_t int_ms, uint32_t fin_ms);

/**
 * Get DTLS timer state.
 * Signature matches mbedtls_ssl_set_timer_t get callback.
 * Returns: -1 if cancelled, 0 if neither expired,
 *           1 if intermediate expired, 2 if final expired.
 */
extern int ports_dtls_timer_get(void* ctx);

/* ---- Platform Init ---- */

/**
 * One-time platform crypto initialization (e.g. psa_crypto_init()).
 * Called before any TLS/DTLS operation. No-op on platforms that don't need it.
 */
extern void ports_crypto_init(void);

#endif  /* PORTS_H_ */
