#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#define MAX_ADDR_LEN 260 /*256 + some for newline*/

uint16_t parse_ipv4_pkt_sz(void *b1, ssize_t len1, void *b2, ssize_t len2);

#endif
