#include "../src/common.h"
#include <assert.h>
#include <stddef.h>

int T0_buff1_5_bytes() {
    uint8_t part_1[] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
    assert(parse_ipv4_pkt_sz(part_1, 5, NULL, 0) == 0x0C0D);
}

int T1_buff1_4_bytes() {
    uint8_t part_1[] = {0x01, 0x02, 0x03, 0x04};
    assert(parse_ipv4_pkt_sz(part_1, 4, NULL, 0) == 0x0304);
}

int T2_buff1_3_bytes_buff2_2_bytes() {
    uint8_t part_1[] = {0x0A, 0x0B, 0x0C};
    uint8_t part_2[] = {0x01, 0x02};
    uint16_t len = parse_ipv4_pkt_sz(part_1, 3, part_2, 2);
    assert(parse_ipv4_pkt_sz(part_1, 3, part_2, 2) == 0x0C01);
}

int T3_buff1_3_bytes_buff2_1_bytes() {
    uint8_t part_1[] = {0x0A, 0x0B, 0x0C};
    uint8_t part_2[] = {0x01};
    uint16_t len = parse_ipv4_pkt_sz(part_1, 3, part_2, 1);
    assert(parse_ipv4_pkt_sz(part_1, 3, part_2, 1) == 0x0C01);
}

int T4_buff1_3_bytes_buff2_0_bytes() {
    uint8_t part_1[] = {0xAA, 0xBB, 0xCC};
    assert(parse_ipv4_pkt_sz(part_1, 3, NULL, 0) == 0x0);
}

int T5_buff1_2_bytes_buff2_2_bytes() {
    uint8_t part_1[] = {0x0A, 0x0B};
    uint8_t part_2[] = {0x01, 0x02};
    assert(parse_ipv4_pkt_sz(part_1, 2, part_2, 2) == 0x0102);
}

int T6_buff1_2_bytes_buff2_1_bytes() {
    uint8_t part_1[] = {0x0A, 0x0B};
    uint8_t part_2[] = {0x01};
    assert(parse_ipv4_pkt_sz(part_1, 2, part_2, 1) == 0x0);
}

int T7_buff1_1_bytes_buff2_4_bytes() {
    uint8_t part_1[] = {0x0A};
    uint8_t part_2[] = {0xFF, 0xEE, 0xDD, 0xCC};
    assert(parse_ipv4_pkt_sz(part_1, 1, part_2, 4) == 0xEEDD);
}

int T8_buff1_1_bytes_buff2_3_bytes() {
    uint8_t part_1[] = {0x0A};
    uint8_t part_2[] = {0x0B, 0x0C, 0x0D};
    assert(parse_ipv4_pkt_sz(part_1, 1, part_2, 4) == 0x0C0D);
}

int T9_buff1_1_bytes_buff2_2_bytes() {
    uint8_t part_1[] = {0x0A};
    uint8_t part_2[] = {0x0B, 0x0C};
    assert(parse_ipv4_pkt_sz(part_1, 1, part_2, 2) == 0x0);
}

int T10_buff1_0_bytes_buff2_5_bytes() {
    uint8_t part_2[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    assert(parse_ipv4_pkt_sz(NULL, 0, part_2, 5) == 0xCCDD);
}

int T11_buff1_0_bytes_buff2_4_bytes() {
    uint8_t part_2[] = {0xAA, 0xBB, 0xCC, 0xDD};
    assert(parse_ipv4_pkt_sz(NULL, 0, part_2, 4) == 0xCCDD);
}

int T12_buff1_0_bytes_buff2_3_bytes() {
    uint8_t part_2[] = {0xAA, 0xBB, 0xCC};
    assert(parse_ipv4_pkt_sz(NULL, 0, part_2, 3) == 0x0);
}

int main() {
    T0_buff1_5_bytes();
    T1_buff1_4_bytes();
    T2_buff1_3_bytes_buff2_2_bytes();
    T3_buff1_3_bytes_buff2_1_bytes();
    T4_buff1_3_bytes_buff2_0_bytes();
    T5_buff1_2_bytes_buff2_2_bytes();
    T6_buff1_2_bytes_buff2_1_bytes();
    T7_buff1_1_bytes_buff2_4_bytes();
    T8_buff1_1_bytes_buff2_3_bytes();
    T9_buff1_1_bytes_buff2_2_bytes();
    T10_buff1_0_bytes_buff2_5_bytes();
    T11_buff1_0_bytes_buff2_4_bytes();
    T12_buff1_0_bytes_buff2_3_bytes();
}
