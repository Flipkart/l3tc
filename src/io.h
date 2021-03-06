#ifndef _IO_H
#define _IO_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif
#include <unistd.h>


struct ring_sz_s {
    ssize_t tun;
    ssize_t conn;
	ssize_t max_allowed;
	int do_resize;
};

typedef struct ring_sz_s ring_sz_t;

int io(int tun_fd, const char* peer_file_path, const char *self_addr_v4, const char *self_addr_v6, int listener_port, const char *ipset_name, int try_reconect_interval, int compression_level, int low_latency_aggressiveness, ring_sz_t *ring_sz);

void trigger_peer_reset();

void trigger_io_loop_stop();

#endif
