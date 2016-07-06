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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

extern const char *__progname;

#define MAX_FILE_PATH_LEN 1024
#define DEFAULT_LISTNER_PORT 15

static void usage(void) {
	/* TODO:3002 Don't forget to update the usage block with the most
	 * TODO:3002 important options. */
	fprintf(stderr, "Usage: %s [OPTIONS]\n",
	    __progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);
	fprintf(stderr, "\n");
	fprintf(stderr, " -d, --debug                              be more verbose.\n");
	fprintf(stderr, " -h, --help                               display help and exit\n");
	fprintf(stderr, " -v, --version                            print version and exit\n");
    fprintf(stderr, " -l, --listenerPort  <port>               listener port (should be the same value across all peers)\n");
    fprintf(stderr, " -p, --peerList  <path>                   path to file containing list of peers (IP v4/v6 addresses or hostnames)\n");
    fprintf(stderr, " -s, --selfAddress  <addr>                hosts own address as seen by peers (IP v4/v6 addresses or hostname)\n");
    fprintf(stderr, " -c, --compLvl  <compression-level>       Compression level between (0: none, 1: fast ... 9: best)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "see manual page " PACKAGE "(8) for more information\n");
}

int main(int argc, char *argv[]) {
	int debug = 1;
	int ch;
    char *peer_file = NULL;
    char *self_addr = NULL;
    int compression_level = DEFAULT_COMPRESSION_LEVEL;
    int listener_port = 15;

	/* TODO:3001 If you want to add more options, add them here. */
	static struct option long_options[] = {
                { "debug", no_argument, 0, 'd' },
                { "help",  no_argument, 0, 'h' },
                { "version", no_argument, 0, 'v' },
                { "peerList", required_argument, 0, 'p' },
                { "selfAddress", required_argument, 0, 's' },
                { "listenerPort", required_argument, 0, 'l' },
                { "compLvl", required_argument, 0, 'c' },
                { 0 }};
	while (1) {
		int option_index = 0;
		ch = getopt_long(argc, argv, "hvdD:l:c:p:s:",
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
            peer_file = strndup(optarg, MAX_FILE_PATH);
			break;
		case 's':
            assert(self_addr == NULL);
            self_addr = strndup(optarg, MAX_ADDR_LEN);
			break;
		case 'c':
			compression_level = atoi(optarg);
			break;
		case 'l':
			listener_port = atoi(optarg);
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

    if ((! error) && self_addr == NULL) {
        error = "Self address not provided";
    }

    if (! error) {
        log_debug("main", "Allocating tun");
        int tun_fd = alloc_tun(tun_up_cmd);
        if (tun_fd <= 0) {
            error = "Could not open tunnel";
        }
    }

    if (! error) {
        if (io(tun_fd, peer_file, self_addr, listener_port) != 0)
            error = "io loop failed";
    }

    free(self_addr);
    free(peer_file);
    if (tun_fd > 0)
        close(tun_fd);
    
    if (error) {
        fatalx(error);
    }

	return EXIT_SUCCESS;
}
