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

static inline int run_routeup_script(const char *if_name, const char *ipset_name, const char *tun_up_cmd) {
    char tun_iface_var[100];
    char ipset_name_var[100];

    int env_var_len = snprintf(tun_iface_var, sizeof(tun_iface_var), "TUN_IFACE=%s", if_name);
    assert(env_var_len > 0 && (unsigned) env_var_len < sizeof(tun_iface_var));
    assert(putenv(tun_iface_var) == 0);

    env_var_len = snprintf(ipset_name_var, sizeof(ipset_name_var), "IPSET_NAME=%s", ipset_name);
    assert(env_var_len > 0 && (unsigned) env_var_len < sizeof(ipset_name_var));
    assert(putenv(ipset_name_var) == 0);
    
    return system(tun_up_cmd);
}

int alloc_tun(const char *tun_up_cmd, const char *ipset_name) {
    const char *dev = "tun%d";
    struct ifreq ifr;
    int fd, err;
    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
        fatal("tun", "open for tun device failed");

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
    int ret = run_routeup_script(ifr.ifr_name, ipset_name, tun_up_cmd);
    if (ret != 0) {
        log_crit("tun", "TUN-UP command '%s' failed, return code was %d", tun_up_cmd, ret);
        close(fd);
        return -1;
    }
    return fd;
}
