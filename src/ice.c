#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ice.h"
#include "mdns.h"
#include "ports.h"
#include "socket.h"
#include "utils.h"

static uint8_t ice_candidate_type_preference(IceCandidateType type) {
  switch (type) {
    case ICE_CANDIDATE_TYPE_HOST:
      return 126;
    case ICE_CANDIDATE_TYPE_SRFLX:
      return 100;
    case ICE_CANDIDATE_TYPE_RELAY:
      return 0;
    default:
      return 0;
  }
}

static uint16_t ice_candidate_local_preference(IceCandidate* candidate) {
  return candidate->addr.port;
}

static void ice_candidate_priority(IceCandidate* candidate) {
  // priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)
  candidate->priority = (1 << 24) * ice_candidate_type_preference(candidate->type) + (1 << 8) * ice_candidate_local_preference(candidate) + (256 - candidate->component);
}

void ice_candidate_create(IceCandidate* candidate, int foundation, IceCandidateType type, Address* addr) {
  memcpy(&candidate->addr, addr, sizeof(Address));
  candidate->type = type;

  snprintf(candidate->foundation, sizeof(candidate->foundation), "%d", foundation);
  // 1: RTP, 2: RTCP
  candidate->component = 1;

  ice_candidate_priority(candidate);

  snprintf(candidate->transport, sizeof(candidate->transport), "%s", "UDP");
}

void ice_candidate_to_description(IceCandidate* candidate, char* description, int length) {
  char addr_string[ADDRSTRLEN];
  char typ_raddr[128];

  memset(typ_raddr, 0, sizeof(typ_raddr));
  addr_to_string(&candidate->raddr, addr_string, sizeof(addr_string));

  switch (candidate->type) {
    case ICE_CANDIDATE_TYPE_HOST:
      snprintf(typ_raddr, sizeof(typ_raddr), "host");
      break;
    case ICE_CANDIDATE_TYPE_SRFLX:
      snprintf(typ_raddr, sizeof(typ_raddr), "srflx raddr %s rport %d", addr_string, candidate->raddr.port);
      break;
    case ICE_CANDIDATE_TYPE_RELAY:
      snprintf(typ_raddr, sizeof(typ_raddr), "relay raddr %s rport %d", addr_string, candidate->raddr.port);
    default:
      break;
  }

  addr_to_string(&candidate->addr, addr_string, sizeof(addr_string));
  snprintf(description, length, "a=candidate:%s %d %s %u %s %d typ %s\r\n",
           candidate->foundation,
           candidate->component,
           candidate->transport,
           (unsigned int)candidate->priority,
           addr_string,
           candidate->addr.port,
           typ_raddr);
}

int ice_candidate_from_description(IceCandidate* candidate, char* description, char* end) {
  char* p = description;
  char type[16];
  char addrstring[ADDRSTRLEN];

  if (strncmp("a=", p, 2) == 0) {
    p += 2;
  }
  if (strncmp("candidate:", p, 10) == 0) {
    p += 10;
  }

  // Null-terminate at line boundary
  char saved = 0;
  if (end && end > description) {
    saved = *end;
    *end = '\0';
  }

  printf("[libpeer] RAW candidate_start: [%s]\n", p);

  // Manual token parsing — sscanf %d is broken on this platform
  // Format: foundation component transport priority address port typ type ...
  char* tok;
  char* saveptr = NULL;
  char linebuf[256];
  strncpy(linebuf, p, sizeof(linebuf) - 1);
  linebuf[sizeof(linebuf) - 1] = '\0';

  // Restore saved char early since we copied to linebuf
  if (end && end > description) {
    *end = saved;
  }

  // Token 1: foundation
  tok = strtok_r(linebuf, " ", &saveptr);
  if (!tok) { LOGE("Missing foundation"); return -1; }
  strncpy(candidate->foundation, tok, 32);
  candidate->foundation[32] = '\0';

  // Token 2: component
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing component"); return -1; }
  candidate->component = (int)strtol(tok, NULL, 10);

  // Token 3: transport
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing transport"); return -1; }
  strncpy(candidate->transport, tok, 32);
  candidate->transport[32] = '\0';

  // Token 4: priority
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing priority"); return -1; }
  candidate->priority = (uint32_t)strtol(tok, NULL, 10);

  // Token 5: address
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing address"); return -1; }
  strncpy(addrstring, tok, ADDRSTRLEN - 1);
  addrstring[ADDRSTRLEN - 1] = '\0';

  // Token 6: port
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing port"); return -1; }
  int port_int = (int)strtol(tok, NULL, 10);

  // Token 7: "typ"
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok || strncmp(tok, "typ", 3) != 0) { LOGE("Missing typ keyword"); return -1; }

  // Token 8: type (host/srflx/relay)
  tok = strtok_r(NULL, " ", &saveptr);
  if (!tok) { LOGE("Missing candidate type"); return -1; }
  strncpy(type, tok, sizeof(type) - 1);
  type[sizeof(type) - 1] = '\0';

  printf("[libpeer] Parsed: comp=%d prio=%d addr=%s port=%d type=%s\n",
         candidate->component, (int)candidate->priority, addrstring, port_int, type);

  if (strncmp(candidate->transport, "UDP", 3) != 0 && strncmp(candidate->transport, "udp", 3) != 0) {
    LOGE("Only UDP transport is supported");
    return -1;
  }

  if (strncmp(type, "host", 4) == 0) {
    candidate->type = ICE_CANDIDATE_TYPE_HOST;
  } else if (strncmp(type, "srflx", 5) == 0) {
    candidate->type = ICE_CANDIDATE_TYPE_SRFLX;
  } else if (strncmp(type, "relay", 5) == 0) {
    candidate->type = ICE_CANDIDATE_TYPE_RELAY;
  } else {
    LOGE("Unknown candidate type: %s", type);
    return -1;
  }

  // Parse address first so family is set, then set port on correct sockaddr
  if (strstr(addrstring, "local") != NULL) {
    if (mdns_resolve_addr(addrstring, &candidate->addr) == 0) {
      LOGW("Failed to resolve mDNS address");
      return -1;
    }
  } else if (addr_from_string(addrstring, &candidate->addr) == 0) {
    LOGE("Failed to parse address: %s", addrstring);
    return -1;
  }

  addr_set_port(&candidate->addr, (uint16_t)port_int);
  printf("[libpeer] ICE candidate: addr=%s port=%d prio=%d type=%s\n", addrstring, port_int, (int)candidate->priority, type);

  return 0;
}
