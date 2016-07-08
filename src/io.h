#ifndef _IO_H
#define _IO_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

int io(int tun_fd, const char* peer_file_path, const char* self_addr, int listener_port);

void reset_peers();
#endif
