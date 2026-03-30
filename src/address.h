#ifndef ADDRESS_H_
#define ADDRESS_H_

#include "config.h"
#if CONFIG_USE_LWIP
#include <lwip/sockets.h>
#include <lwip/inet.h>
/* Stub sockaddr_in6 for lwIP builds without IPv6 */
#if !defined(LWIP_IPV6) || !LWIP_IPV6
#ifndef _SOCKADDR_IN6_DEFINED
#define _SOCKADDR_IN6_DEFINED
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
struct sockaddr_in6 {
  uint8_t          sin6_len;
  uint8_t          sin6_family;
  uint16_t         sin6_port;
  uint32_t         sin6_flowinfo;
  struct in6_addr  sin6_addr;
  uint32_t         sin6_scope_id;
};
#endif
#endif
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#include <stdint.h>

#define ADDRSTRLEN INET6_ADDRSTRLEN

typedef struct Address {
  uint8_t family;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  uint16_t port;
} Address;

void addr_set_family(Address* addr, int family);

void addr_set_port(Address* addr, uint16_t port);

int addr_inet6_validate(const char* ipv6, size_t len, Address* addr);

int addr_inet_validate(const char* ipv4, size_t len, Address* addr);

int addr_to_string(const Address* addr, char* buf, size_t len);

int addr_from_string(const char* str, Address* addr);

int addr_equal(const Address* a, const Address* b);

#endif  // ADDRESS_H_
