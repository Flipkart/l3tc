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

int alloc_tun(const char *tun_up_cmd) {
    const char *dev = "tun%d";
    struct ifreq ifr;
    int fd, err;
    char buff[100];

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
    log_info("tun", "Opened device %s [fd: %d], will run the command [%s] now", ifr.ifr_name, fd, tun_up_cmd);
    int env_var_len = snprintf(buff, sizeof(buff), "TUN_IFACE=%s", ifr.ifr_name);
    assert(env_var_len > 0 && (unsigned) env_var_len < sizeof(buff));
    assert(putenv(buff) == 0);
    int ret = system(tun_up_cmd);
    if (ret != 0) {
        log_crit("tun", "TUN-UP command '%s' failed, return code was %d", tun_up_cmd, ret);
        return -1;
    }
    return fd;
}
