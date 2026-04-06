/**
 * Platform Abstraction Layer — Realtek RTL8721DM (AmebaD)
 *
 * FreeRTOS + LwIP + AmebaD SDK
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "lwip/netif.h"
#include "lwip/sys.h"

#include "ports.h"
#include "utils.h"

/* ---- Timing ---- */

uint32_t ports_get_epoch_time(void) {
  return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

void ports_sleep_ms(int ms) {
  vTaskDelay(pdMS_TO_TICKS(ms));
}

/* ---- Memory ---- */

uint32_t ports_get_free_heap(void) {
  return (uint32_t)xPortGetFreeHeapSize();
}

/* ---- Network ---- */

int ports_get_host_addr(Address* addr, const char* iface_prefix) {
  struct netif* netif;
  int i;
  int ret = 0;
  /* Prefer netif_default (STA) — netif_list starts with the AP interface
   * on AmebaD, which would advertise the wrong IP for ICE. */
  struct netif* target = netif_default ? netif_default : netif_list;
  for (netif = target; netif != NULL; netif = netif->next) {
    switch (addr->family) {
      case AF_INET6:
#if defined(LWIP_IPV6) && LWIP_IPV6
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
          if (!ip6_addr_isany(netif_ip6_addr(netif, i))) {
            memcpy(&addr->sin6.sin6_addr, netif_ip6_addr(netif, i), 16);
            ret = 1;
            break;
          }
        }
#endif
        break;
      case AF_INET:
      default:
        if (!ip_addr_isany(&netif->ip_addr)) {
#if LWIP_IPV4 && LWIP_IPV6
          memcpy(&addr->sin.sin_addr, &netif->ip_addr.u_addr.ip4, 4);
#else
          memcpy(&addr->sin.sin_addr, &netif->ip_addr, 4);
#endif
          ret = 1;
        }
        break;
    }
    if (ret) break;
  }
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

/* AmebaD hardware RNG */
extern unsigned int Gen_RandomSeed(void);

int ports_hardware_entropy(void* data, unsigned char* output,
                           size_t len, size_t* olen) {
  (void)data;
  size_t i = 0;
  while (i < len) {
    unsigned int rnd = Gen_RandomSeed();
    size_t copy = (len - i < 4) ? (len - i) : 4;
    memcpy(output + i, &rnd, copy);
    i += copy;
  }
  *olen = len;
  return 0;
}

/* ---- DTLS Timer ---- */

struct PortsDtlsTimer {
  uint32_t start_ms;
  uint32_t int_ms;
  uint32_t fin_ms;
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
  t->int_ms = int_ms;
  t->fin_ms = fin_ms;
  if (fin_ms != 0)
    t->start_ms = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

int ports_dtls_timer_get(void* ctx) {
  PortsDtlsTimer* t = (PortsDtlsTimer*)ctx;
  if (t->fin_ms == 0) return -1;  /* cancelled */
  uint32_t elapsed = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS) - t->start_ms;
  if (elapsed >= t->fin_ms) return 2;  /* final delay expired */
  if (elapsed >= t->int_ms) return 1;  /* intermediate delay expired */
  return 0;
}

/* ---- Platform Init ---- */

#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif

void ports_crypto_init(void) {
#if defined(MBEDTLS_PSA_CRYPTO_C)
  psa_crypto_init();
#endif
}
