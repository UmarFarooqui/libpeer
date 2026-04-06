/**
 * Platform Abstraction Layer — Linux / POSIX
 *
 * Original libpeer desktop implementation.
 */
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#include "mbedtls/timing.h"

#include "ports.h"
#include "utils.h"

/* ---- Timing ---- */

uint32_t ports_get_epoch_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint32_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void ports_sleep_ms(int ms) {
  usleep(ms * 1000);
}

/* ---- Memory ---- */

uint32_t ports_get_free_heap(void) {
  return 0; /* not meaningful on Linux */
}

/* ---- Network ---- */

int ports_get_host_addr(Address* addr, const char* iface_prefix) {
  int ret = 0;
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    LOGE("getifaddrs failed: %s", strerror(errno));
    return -1;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;
    if (ifa->ifa_addr->sa_family != addr->family) continue;

    if (iface_prefix && strlen(iface_prefix) > 0) {
      if (strncmp(ifa->ifa_name, iface_prefix, strlen(iface_prefix)) != 0)
        continue;
    } else {
      if ((ifa->ifa_flags & IFF_UP) == 0) continue;
      if ((ifa->ifa_flags & IFF_RUNNING) == 0) continue;
      if ((ifa->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK) continue;
    }

    switch (ifa->ifa_addr->sa_family) {
      case AF_INET6:
        memcpy(&addr->sin6, ifa->ifa_addr, sizeof(struct sockaddr_in6));
        break;
      case AF_INET:
      default:
        memcpy(&addr->sin, ifa->ifa_addr, sizeof(struct sockaddr_in));
        break;
    }
    ret = 1;
    break;
  }
  freeaddrinfo(ifaddr);
  return ret;
}

int ports_resolve_addr(const char* host, Address* addr) {
  char addr_string[ADDRSTRLEN];
  int ret = -1;
  struct addrinfo hints, *res, *p;
  int status;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
    LOGE("getaddrinfo error: %d", status);
    return ret;
  }

  addr_set_family(addr, AF_INET);
  for (p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family == addr->family) {
      switch (addr->family) {
        case AF_INET6:
          memcpy(&addr->sin6, p->ai_addr, sizeof(struct sockaddr_in6));
          break;
        case AF_INET:
        default:
          memcpy(&addr->sin, p->ai_addr, sizeof(struct sockaddr_in));
          break;
      }
      ret = 0;
    }
  }

  addr_to_string(addr, addr_string, sizeof(addr_string));
  LOGI("Resolved %s -> %s", host, addr_string);
  freeaddrinfo(res);
  return ret;
}

/* ---- Entropy ---- */

int ports_hardware_entropy(void* data, unsigned char* output,
                           size_t len, size_t* olen) {
  /* Linux: use /dev/urandom or let mbedTLS default entropy handle it.
   * This is a fallback in case it's called directly. */
  (void)data;
  FILE* f = fopen("/dev/urandom", "rb");
  if (!f) return -1;
  *olen = fread(output, 1, len, f);
  fclose(f);
  return 0;
}

/* ---- DTLS Timer ---- */

/*
 * On Linux, use mbedtls_timing_delay_context which internally uses
 * gettimeofday(). We wrap it behind the PAL interface.
 */
struct PortsDtlsTimer {
  mbedtls_timing_delay_context ctx;
};

PortsDtlsTimer* ports_dtls_timer_alloc(void) {
  PortsDtlsTimer* t = calloc(1, sizeof(PortsDtlsTimer));
  return t;
}

void ports_dtls_timer_free(PortsDtlsTimer* timer) {
  free(timer);
}

void ports_dtls_timer_set(void* ctx, uint32_t int_ms, uint32_t fin_ms) {
  PortsDtlsTimer* t = (PortsDtlsTimer*)ctx;
  mbedtls_timing_set_delay(&t->ctx, int_ms, fin_ms);
}

int ports_dtls_timer_get(void* ctx) {
  PortsDtlsTimer* t = (PortsDtlsTimer*)ctx;
  return mbedtls_timing_get_delay(&t->ctx);
}

/* ---- Platform Init ---- */

void ports_crypto_init(void) {
  /* No-op on Linux */
}
