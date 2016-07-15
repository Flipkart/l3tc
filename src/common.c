#include "common.h"

#include <assert.h>
#include <arpa/inet.h>

uint16_t parse_ipv4_pkt_sz(void *b1, ssize_t len1, void *b2, ssize_t len2) {
    if (b1 == NULL && b2 == NULL) return 0;

    assert(len1 >= 0);
    assert(len2 >= 0);

    uint16_t pkt_len;
    if (len1 >= 4) {
        pkt_len = *((uint16_t *) b1 + 1);
    } else if (len1 == 3 && len2 >= 1) {
        uint8_t two_bytes[2];
        two_bytes[0] = *((uint8_t *) (b1 + 2));
        two_bytes[1] = *(uint8_t *) b2;
        pkt_len = *(uint16_t *) two_bytes;
    } else if (len1 <= 2 && (len1 + len2) >= 4) {
        pkt_len = *(uint16_t *)(b2 + 2 - len1);
    } else {
        pkt_len = 0;
    }
    return ntohs(pkt_len);
}

