#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#define TUN_RING_SZ 1024*1024 /* 1 MB, must be greater than 64kB for IPv4, need to check limits in IPv6 */
#define CONN_RING_SZ 128*1024 /* 128 KB, can fit atleast 2 IPv4 packets */
#define MAX_RING_SZ 16*1024*1024 /* 16 MB */
#define SOCK_BUFF_SZ 128*1024

#endif

