#include "tun.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

int alloc_tun() {
    const char *dev = "tun%d";
    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
        fatal("tun", "ioctl call for tun device failed");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN; 
    if(*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0){
        fatal("tun", "ioctl TUNSETIFF call for tun device failed");
        close(fd);
        return err;
    }
    return fd;
}
