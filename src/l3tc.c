/* -*- mode: c; c-file-style: "openbsd" -*- */
/* TODO:5002 You may want to change the copyright of all files. This is the
 * TODO:5002 ISC license. Choose another one if you want.
 */
/*
 * Copyright (c) 2014 Janmejay Singh <singh.janmejay@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "l3tc.h"
#include "common.h"
#include "tun.h"
#include "io.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <signal.h>

extern const char *__progname;

#define MAX_FILE_PATH_LEN 1024
#define DEFAULT_LISTNER_PORT 15
#define MAX_IPSET_NAME_LEN 64

static void usage(void) {
	/* TODO:3002 Don't forget to update the usage block with the most
	 * TODO:3002 important options. */
	fprintf(stderr, "Usage: %s [OPTIONS]\n",
	    __progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);
	fprintf(stderr, "\n");
	fprintf(stderr, " -d, --debug                                      be more verbose.\n");
	fprintf(stderr, " -h, --help                                       display help and exit\n");
	fprintf(stderr, " -v, --version                                    print version and exit\n");
    fprintf(stderr, " -l, --listenerPort  <port>                       listener port (should be the same value across all peers)\n");
    fprintf(stderr, " -p, --peerList  <path>                           path to file containing list of peers (IP v4/v6 addresses or hostnames)\n");
    fprintf(stderr, " -4, --selfIpv4  <addr>                           hosts own address as seen by peers (IP v4)\n");
    fprintf(stderr, " -6, --selfIpv6  <addr>                           hosts own address as seen by peers (IP v6)\n");
    fprintf(stderr, " -c, --compLvl  <compression-level>               compression level between (0: none, 1: fast ... 9: best)\n");
    fprintf(stderr, " -s, --setName  <ipset>                           ipset set-name to be used to record peers for selectively compressing flows\n");
    fprintf(stderr, " -u, --upScript <route-up cmd>                    command for setting-up routing (run once tunnel is up)\n");
    fprintf(stderr, " -r, --tryReconnectInterval <seconds>             least number of seconds to wait before re-attempting connect with failed peers\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "see manual page " PACKAGE "(8) for more information\n");
}

void wireup_signals() {
    assert(signal(SIGINT, trigger_io_loop_stop) != SIG_ERR);
    assert(signal(SIGTERM, trigger_io_loop_stop) != SIG_ERR);
    assert(signal(SIGHUP, trigger_peer_reset) != SIG_ERR);
}

int main(int argc, char *argv[]) {
	int debug = 1;
	int ch;
    char *peer_file = NULL;
    char *self_addr_v4 = NULL;
    char *self_addr_v6 = NULL;
    int compression_level = DEFAULT_COMPRESSION_LEVEL;
    int listener_port = 15;
    char *ipset_name = NULL;
    char *route_up_cmd = NULL;
    int try_reconnect_itvl = 30;

	/* TODO:3001 If you want to add more options, add them here. */
	static struct option long_options[] = {
                { "debug", no_argument, 0, 'd' },
                { "help",  no_argument, 0, 'h' },
                { "version", no_argument, 0, 'v' },
                { "peerList", required_argument, 0, 'p' },
                { "selfIpv4", required_argument, 0, '4' },
                { "selfIpv6", required_argument, 0, '6' },
                { "listenerPort", required_argument, 0, 'l' },
                { "compLvl", required_argument, 0, 'c' },
                { "setName", required_argument, 0, 's' },
                { "upCmd", required_argument, 0, 'u' },
                { "tryReconnectInterval", required_argument, 0, 'r' },
                { 0 }};
	while (1) {
		int option_index = 0;
		ch = getopt_long(argc, argv, "hvdD:l:c:p:4:6:s:u:r:",
		    long_options, &option_index);
		if (ch == -1) break;
		switch (ch) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			fprintf(stdout, "%s\n", PACKAGE_VERSION);
			exit(0);
			break;
		case 'd':
			debug++;
			break;
		case 'D':
			log_accept(optarg);
			break;
		case 'p':
            assert(peer_file == NULL);
            peer_file = strndup(optarg, MAX_FILE_PATH_LEN);
			break;
		case '4':
            assert(self_addr_v4 == NULL);
            self_addr_v4 = strndup(optarg, MAX_ADDR_LEN);
			break;
		case '6':
            assert(self_addr_v6 == NULL);
            self_addr_v6 = strndup(optarg, MAX_ADDR_LEN);
			break;
		case 'c':
			compression_level = atoi(optarg);
			break;
		case 'l':
			listener_port = atoi(optarg);
			break;
        case 's':
            assert(ipset_name == NULL);
            ipset_name = strndup(optarg, MAX_IPSET_NAME_LEN);
			break;
        case 'u':
            assert(route_up_cmd == NULL);
            route_up_cmd = strndup(optarg, MAX_FILE_PATH_LEN);
			break;
        case 'r':
            try_reconnect_itvl = atoi(optarg);
            break;
		default:
			fprintf(stderr, "unknown option `%c'\n", ch);
			usage();
			exit(1);
		}
	}

	log_init(debug, __progname);

    const char *error = NULL;

    if ((! error) && (peer_file == NULL || access(peer_file, R_OK) != 0)) {
        error = "Peer file not found";
    }

    if ((! error) && (self_addr_v4 == NULL && self_addr_v6 == NULL)) {
        error = "Self address not provided, please provide either v4 or v6.";
    }

    if ((! error) && (route_up_cmd == NULL)) {
        error = "Route-up cmd not provided";
    }

    if (ipset_name == NULL) {
        ipset_name = strdup("l3tc");
    }

    int tun_fd;
    if (! error) {
        log_debug("main", "Allocating tun");
        tun_fd = alloc_tun(route_up_cmd, ipset_name);
        if (tun_fd <= 0) {
            error = "Could not open tunnel";
        }
    }

    if (! error) {
        wireup_signals();
        if (io(tun_fd, peer_file, self_addr_v4, self_addr_v6, listener_port, ipset_name, try_reconnect_itvl, compression_level) != 0) error = "io loop failed";
    }

    free(self_addr_v4);
    free(self_addr_v6);
    free(ipset_name);
    free(route_up_cmd);
    free(peer_file);
    if (tun_fd > 0)
        close(tun_fd);
    
    if (error) {
        fatalx(error);
    }

	return EXIT_SUCCESS;
}
