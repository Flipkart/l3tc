#include "io.h"
#include "common.h"
#include "ba_htab.h"
#include "log.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <assert.h>
#include <sys/uio.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#define LISTEN_BACKLOG 1024
#define INET_ADDR_STRING_LEN 48

#define IPv4_ADDR_LEN sizeof(((struct in_addr *)0)->s_addr)
#define IPv6_ADDR_LEN sizeof(((struct in6_addr *)0)->s6_addr)

#define MAX_NW_ADDR_LEN ((IPv6_ADDR_LEN > IPv4_ADDR_LEN) ? IPv6_ADDR_LEN : IPv4_ADDR_LEN)

#define TUN_RING_SZ 1024*1024 /* 1 MB, must be greater than 64kB for IPv4, need to check limits in IPv6 */
#define CONN_RING_SZ 128*1024 /* 128 KB, can fit atleast 2 IPv4 packets */

typedef struct io_ctx_s io_ctx_t;
typedef struct io_sock_s io_sock_t;

typedef struct ring_buff_s ring_buff_t;

struct ring_buff_s {
    void *buff;
    ssize_t sz, start, end;
    int wraped;
};

struct tun_pkt_buff_s {
    void *buff;
    ssize_t capacity, len, current_pkt_len;
};

typedef struct tun_pkt_buff_s tun_pkt_buff_t;

struct io_sock_s {
    LIST_ENTRY(io_sock_s) link;
    int fd;
    io_ctx_t *ctx;
    enum {
		lstn,
		conn,
		tun
	} typ;
    int alive;
    struct epoll_event evt;
    union {
        struct {
            uint8_t peer[MAX_NW_ADDR_LEN];
            int af;
            int outbound;
            ring_buff_t rx, tx;
        } conn;
        struct {
            ring_buff_t tx;
            tun_pkt_buff_t r_buff, w_buff;
        } tun;
    } d;
};

#define NET_ADDR(field_name)                    \
    uint8_t field_name[MAX_NW_ADDR_LEN]

struct passive_peer_s {
    LIST_ENTRY(passive_peer_s) link;
    struct addrinfo *addr_info;    
    NET_ADDR(addr);
    char humanified_address[INET_ADDR_STRING_LEN];
};

typedef struct passive_peer_s passive_peer_t;

#define USING_IPV4 0x1
#define USING_IPV6 0x2

struct io_ctr_s {
    uint64_t b, p, drop_b, drop_p;
};

typedef struct io_ctr_s io_ctr_t;

struct io_ctx_s {
    LIST_HEAD(all, io_sock_s) non_conns;
    batab_t live_conns; /* to passive and active peers */
    LIST_HEAD(dpp, passive_peer_s) disconnected_passive_peers;
    batab_t passive_peers;
    int tun_fd;
    int epoll_fd;
    NET_ADDR(self_v4);
    NET_ADDR(self_v6);
    int using_af;
    ring_buff_t *tun_tx;
    const char *ipset_name;
    io_ctr_t c_tun_rx, c_tun_tx, c_world_rx, c_world_tx;
};

static inline void destroy_sock(io_sock_t *sock);

static inline void destroy_io_ctx(io_ctx_t *ctx) {
    if (ctx == NULL) return;

    batab_entry_t *e;
    batab_foreach_do((&ctx->live_conns), e) {
        destroy_sock(e->value);
    }
    
    batab_destory(&ctx->live_conns);

    while (ctx->non_conns.lh_first != NULL)
        destroy_sock(ctx->non_conns.lh_first);

    batab_destory(&ctx->passive_peers);

    free(ctx);
}

static inline void destroy_ring_buff(ring_buff_t *ring) {
    DBG("io", L("destroying ring: %p { sz=%zd, start=%zd, end=%zd, wrapped=%d }"), ring, ring->sz, ring->start, ring->end, ring->wraped);
    free(ring->buff);
}

static inline void destroy_conn_sock_data(io_sock_t *sock) {
    io_ctx_t *ctx = sock->ctx;
    assert(sock->typ == conn);
    if (sock->fd >= 0) {
        batab_remove(&ctx->live_conns, sock->d.conn.peer);
        if (sock->d.conn.outbound) {
            passive_peer_t *pp = batab_get(&ctx->passive_peers, sock->d.conn.peer);
            assert(pp != NULL);
            LIST_INSERT_HEAD(&ctx->disconnected_passive_peers, pp, link);
        }
    }
    destroy_ring_buff(&sock->d.conn.tx);
    destroy_ring_buff(&sock->d.conn.rx);
}

static inline void destroy_tun_sock_data(io_sock_t *sock) {
    destroy_ring_buff(&sock->d.tun.tx);
    free(sock->d.tun.w_buff.buff);
    free(sock->d.tun.r_buff.buff);
}

static inline int setup_conn_route(io_sock_t *sock) {
    assert(sock->typ == conn);
    char addr_buff[MAX_ADDR_LEN];
    char cmd_buff[MAX_ADDR_LEN + 100];
    int af = sock->d.conn.af;

    if (inet_ntop(af, sock->d.conn.peer, addr_buff, sizeof(addr_buff)) == NULL) {
        log_warn("io", L("Could not determine peer-name for fd: %d, dropping"), sock->fd);
        return -1;
    }

    int len = snprintf(cmd_buff, sizeof(cmd_buff), "ipset add %s %s", sock->ctx->ipset_name, addr_buff);
    assert(len < (int) sizeof(cmd_buff) && len > 0);

    int ret = system(cmd_buff);

    DBG("io", L("Mark routed (status: %d) cmd: %s"), ret, cmd_buff);

    return ret;
}

static inline int drop_conn_route(io_sock_t *sock) {
    assert(sock->typ == conn);
    char addr_buff[MAX_ADDR_LEN];
    char cmd_buff[MAX_ADDR_LEN + 100];
    int af = sock->d.conn.af;

    if (inet_ntop(af, sock->d.conn.peer, addr_buff, sizeof(addr_buff)) == NULL) {
        log_warn("io", L("Could not determine peer-name for fd: %d, dropping"), sock->fd);
        return -1;
    }

    int len = snprintf(cmd_buff, sizeof(cmd_buff), "ipset del %s %s", sock->ctx->ipset_name, addr_buff);
    assert(len < (int) sizeof(cmd_buff) && len > 0);

    int ret = system(cmd_buff);

    DBG("io", L("Unmark routed (status: %d) cmd: %s"), ret, cmd_buff);
    
    return ret;
}

static inline void destroy_sock(io_sock_t *sock) {
    if (NULL == sock) return;
    log_debug("io", L("destroying socket of type: %d (fd: %d)"), sock->typ, sock->fd);

    if (conn == sock->typ) {
        if (drop_conn_route(sock) != 0) {
            log_warn("io", L("Couldn't drop route to %d"), sock->fd);
        }
    } else {
        LIST_REMOVE(sock, link);
    }
    
    if (epoll_ctl(sock->ctx->epoll_fd, EPOLL_CTL_DEL, sock->fd, NULL)) {
        log_warn("io", L("removal from epoll context for fd: %d failed"), sock->fd);
    }
    if (conn == sock->typ) {
        destroy_conn_sock_data(sock);
    } else if (tun == sock->typ) {
        destroy_tun_sock_data(sock);
    }

    if (sock->fd > 0) {
        close(sock->fd);
        sock->fd = -1;
    }

    free(sock);
}

static inline int set_no_block(int fd) {
    int flags = 0;
    if((flags = fcntl(fd, F_GETFL)) != -1) {
		flags |= O_NONBLOCK;
		flags = fcntl(fd, F_SETFL, flags);
	}
    return flags == -1 ? -1 : 0;
}

typedef int (type_specific_initializer_t)(io_sock_t *sock, void *ts_init_ctx);

static inline int add_sock(io_ctx_t *ctx, int fd, int typ, type_specific_initializer_t *ts_init, void *ts_init_ctx) {
    log_debug("io", L("creating socket of type: %d (fd: %d)"), typ, fd);
    if (set_no_block(fd) != 0) {
        log_warn("io", L("failed to make socket non-blocking, rejecting socket %d"), fd);
        close(fd);
        return -1;
    }
    io_sock_t *sock = calloc(1, sizeof(io_sock_t));
    if (sock == NULL) {
        log_warn("io", L("failed to allocate memory for listerner socket object, closing fd"));
        close(fd);
        return -1;
    }
    sock->fd = fd;
    sock->ctx = ctx;
    sock->typ = typ;

    if (ts_init != NULL) {
        if (ts_init(sock, ts_init_ctx) != 0) {
            log_warn("io", L("could not successfully initialize type-specific context for fd: %d"), fd);
            destroy_sock(sock);
            return -1;
        }
    }

    sock->evt.events = EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLET;
    sock->evt.data.ptr = sock;
    
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sock->fd, &sock->evt) != 0) {
        log_warn("io", L("failed to add fd to polling context"));
        destroy_sock(sock);
        return -1;
    }

    if (sock->typ == conn) {
        if (setup_conn_route(sock) != 0) {
            log_warn("io", L("Route-setup failed, dropping conn."));
            destroy_sock(sock);
            return -1;
        }
    } else {
        LIST_INSERT_HEAD(&ctx->non_conns, sock, link);
    }

    return 0;
}

static inline int init_backlog_ring(ring_buff_t *rbuff, size_t sz) {
    if (NULL == (rbuff->buff = malloc(sz))) {
        return -1;
    }
    rbuff->sz = sz;
    rbuff->start = rbuff->end = 0;
    rbuff->wraped = 0;
    DBG("io", L("backlog ring: %p { sz=%zd, start=%zd, end=%zd, wrapped=%d } initialized"), rbuff, rbuff->sz, rbuff->start, rbuff->end, rbuff->wraped);
    return 0;
}

#define INITIAL_TUN_PKT_BUFF_SZ 4096
#define MAX_L3_PKT_SZ 0xFFFF /* check hop-by-hop stuff for IPv6, 0xFFFF will do for IPv4 though */

static int init_tun_tx_backlog_ring(io_sock_t *sock, void *io_ctx) {
    DBG("io", L("initializing tun state"));
    assert(io_ctx != NULL);
    io_ctx_t *ctx = (io_ctx_t *) io_ctx;
    if (init_backlog_ring(&sock->d.tun.tx, TUN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate tx-backlog ring for tun"));
        return -1;
    }
    if ((sock->d.tun.w_buff.buff = malloc(INITIAL_TUN_PKT_BUFF_SZ)) == NULL) {
        log_crit("io", L("couldn't allocate write-pkt-buff for tun"));
        destroy_ring_buff(&sock->d.tun.tx);
        return -1;
    }
    if ((sock->d.tun.r_buff.buff = malloc(MAX_L3_PKT_SZ)) == NULL) {
        log_crit("io", L("couldn't allocate read-pkt-buff for tun"));
        free(sock->d.tun.w_buff.buff);
        destroy_ring_buff(&sock->d.tun.tx);
        return -1;
    }
    sock->d.tun.r_buff.capacity = sock->d.tun.w_buff.capacity = INITIAL_TUN_PKT_BUFF_SZ;
    sock->d.tun.r_buff.len = sock->d.tun.w_buff.len = 0;
    sock->d.tun.r_buff.current_pkt_len = sock->d.tun.w_buff.current_pkt_len = 0;
    
    ctx->tun_tx = &sock->d.tun.tx;
    return 0;
}

static void free_passive_peer(void *_pp);

static io_ctx_t * init_io_ctx(int tun_fd, const char *self_addr_v4, const char *self_addr_v6, const char *ipset_name) {
    int epoll_fd;
    
#	if defined(EPOLL_CLOEXEC) && defined(HAVE_EPOLL_CREATE1)
	log_debug("io", L("using epoll_create1"));
	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if((epollfd < 0) && (ENOSYS == errno))
#	endif
	{
		log_warnx("io", L("uses epoll_create"));
		/* Just provide some number, kernel ignores it anyway */
		epoll_fd = epoll_create(10);
	}

    if (epoll_fd < 0) {
        log_warn("io", L("Could not create epoll-ctx"));
        return NULL;
    }

    io_ctx_t *ctx = calloc(1, sizeof(io_ctx_t));
    if (NULL == ctx) {
        log_warn("io", L("Could not allocate mem for ctx"));
        close(epoll_fd);
        return NULL;
    }

    ctx->epoll_fd = epoll_fd;
    ctx->tun_fd = tun_fd;
    ctx->ipset_name = ipset_name;
    LIST_INIT(&ctx->disconnected_passive_peers);
    LIST_INIT(&ctx->non_conns);
    if (self_addr_v4 != NULL) {
        if (inet_pton(AF_INET, self_addr_v4, ctx->self_v4) != 1 /* 1 => success */) {
            log_crit("io", L("Could not convert given IPv4 self-address (%s) to binary"), self_addr_v4);
            destroy_io_ctx(ctx);
            return NULL;
        }
        ctx->using_af |= USING_IPV4;
    }
    if (self_addr_v6 != NULL) {
        if (inet_pton(AF_INET6, self_addr_v6, ctx->self_v6) != 1 /* 1 => success */) {
            log_crit("io", L("Could not convert given IPv6 self-address (%s) to binary"), self_addr_v6);
            destroy_io_ctx(ctx);
            return NULL;
        }
        ctx->using_af |= USING_IPV6;
    }
    if (ctx->using_af == 0) {
        log_crit("io", L("Both IPv4 and IPv6 for 'self' not provided."));
        destroy_io_ctx(ctx);
        return NULL;
    }
    if (batab_init(&ctx->passive_peers, offsetof(passive_peer_t, addr), MAX_NW_ADDR_LEN, free_passive_peer, "passive-peers") != 0) {
        log_crit("io", L("Couldn't initialize passive-peers map"));
        destroy_io_ctx(ctx);
        return NULL;
    }
    if (batab_init(&ctx->live_conns, offsetof(io_sock_t, d.conn.peer), MAX_NW_ADDR_LEN, NULL, "live-conn") != 0) {
        log_crit("io", L("Couldn't initialize live-sockets map"));
        destroy_io_ctx(ctx);
        return NULL;
    }
    DBG("io", L("adding tun: %d"), tun_fd);
    if (add_sock(ctx, tun_fd, tun, init_tun_tx_backlog_ring, ctx) != 0) {
        log_crit("io", L("Couldn't add tun to io-ctx"));
    }
    return ctx;
}

static int setup_listener(io_ctx_t *ctx, int listener_port) {
    char buff[8];
    struct addrinfo hints, *res = NULL, *r;
    int max_socks, num_socks;
    memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET; /* hardcode IPv4 for now, debug why it delivers AF_INET connection as IPv6 on the other side */
	hints.ai_socktype = SOCK_STREAM;
    snprintf(buff, sizeof(buff), "%d", listener_port);
    int ret = getaddrinfo(NULL, buff, &hints, &res);
    if (ret != 0) {
        log_crit("io", L("Couldn't get addr-info for listen: %s"), gai_strerror(ret));
        return -1;
    }
    int on = 1;
    
    for (max_socks = 0, num_socks = 0, r = res;
         r != NULL;
         r = r->ai_next, max_socks++) {
        
		int sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (sock < 0) {
            log_warn("io", L("error in creating tcp listening socket"));
            continue;
		}

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
			log_warn("io", L("setting reuse-addr failed"));
            close(sock);
			continue;
		}

        int sockflags;

        if ((sockflags = fcntl(sock, F_GETFL)) == -1) {
            log_warn("io", L("couldn't get socket-flags"));
            close(sock);
            continue;
		}

        sockflags |= O_NONBLOCK;
        if (fcntl(sock, F_SETFL, sockflags) == -1) {
            log_warn("io", L("failed to make socket non-blocking"));
            close(sock);
            continue;
        }

        if(bind(sock, r->ai_addr, r->ai_addrlen) < 0) {
            log_warn("io", L("failed to bind listener socket"));
			close(sock);
			continue;
		}

        if(listen(sock, LISTEN_BACKLOG) < 0) {
			log_warn("io", L("failed to tcp-listen"));
			close(sock);
			continue;
		}


        if (add_sock(ctx, sock, lstn, NULL, NULL) != 0) {
            log_warn("io", L("failed to add listener-socket"));
            close(sock);
            continue;
        }
        num_socks++;
	}

    freeaddrinfo(res);

    if (num_socks != max_socks) {
        log_warn("io", L("Listening to %d sockets, which is less than expected %d"), num_socks, max_socks);
    }

    if (num_socks == 0) {
        log_warn("io", L("Failed to setup listener, none of expected %d sockets initialized correctly"), max_socks);
        return -1;
    }

    return 0;
}

static int do_peer_reset = 0;
static int do_stop = 0;


struct conn_sock_info_s {
    uint8_t *addr;
    int af;
};

typedef struct conn_sock_info_s conn_sock_info_t;

static int init_conn_sock(io_sock_t *sock, void *_addr_info) {
    conn_sock_info_t * addr_info = (conn_sock_info_t *) _addr_info;
    io_ctx_t *ctx = sock->ctx;
    memcpy(sock->d.conn.peer, addr_info->addr, MAX_NW_ADDR_LEN);
    sock->d.conn.af = addr_info->af;
    if (init_backlog_ring(&sock->d.conn.tx, CONN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate tx-backlog ring for sock: %d"), sock->fd);
        return -1;
    }
    if (init_backlog_ring(&sock->d.conn.rx, CONN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate rx-backlog ring for sock: %d"), sock->fd);
        return -1;
    }
    if (batab_put(&ctx->live_conns, sock, NULL) != 0) {
        log_crit("io", L("couldn't wire-up lookup for sock: %d"), sock->fd);
        return -1;
    }
    return 0;
}

static int init_out_conn_sock(io_sock_t *sock, void *_peer) {
    passive_peer_t *peer = (passive_peer_t *) _peer;
    conn_sock_info_t addr_info = { .addr = peer->addr, .af = peer->addr_info->ai_family};
    int ret = init_conn_sock(sock, &addr_info);
    sock->d.conn.outbound = 1;
    return ret;
}

static int setup_outbound_connection(io_ctx_t *ctx, passive_peer_t *peer) {
    struct addrinfo *r = peer->addr_info;
    assert(peer->addr_info != NULL);
    int c_fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    int failed = 0;
    if (c_fd < 0) {
        log_warn("io", L("could not create socket for connecting to peer: %s"), peer->humanified_address);
        return -1;
    }
    if (connect(c_fd, r->ai_addr, r->ai_addrlen) == 0) {
        log_info("io", L("connnected as client to peer: %s"), peer->humanified_address);
        if (add_sock(ctx, c_fd, conn, init_out_conn_sock, peer) != 0) {
            log_warn("io", L("Failed to add passive-peer %s socket to io-ctx"), peer->humanified_address);
            failed = 1;
        }
    } else {
        log_warn("io", L("failed to connect to peer: %s, will try later"), peer->humanified_address);
        failed = 1;
    }
    if (failed) {
        close(c_fd);
        c_fd = -1;
    }
    assert(peer->addr_info != NULL);
    return c_fd;
}

static passive_peer_t *create_passive_peer(struct addrinfo *r, uint8_t *nw_addr) {
    passive_peer_t *pp = malloc(sizeof(passive_peer_t));
    if (pp == NULL) return NULL;
    assert(r->ai_next == NULL);
    assert(r != NULL);
    pp->addr_info = r;
    memcpy(pp->addr, nw_addr, MAX_NW_ADDR_LEN);
    if (inet_ntop(pp->addr_info->ai_family, pp->addr, pp->humanified_address, INET_ADDR_STRING_LEN) == NULL) {
        log_warn("io", L("Failed to copy human-readable addr for endpoint"));
    }
    return pp;
}

static void free_passive_peer(void *_pp) {
    passive_peer_t *pp = (passive_peer_t *) _pp;
    assert(pp != NULL);
    free(pp->addr_info);
    free(pp);
}

static int capture_passive_peer(batab_t *tab, uint8_t *nw_addr, struct addrinfo *r, const char *host_buff, const char *port_buff, int *do_free_addr_info) {
    if (batab_get(tab, nw_addr) == NULL) {
        passive_peer_t *pp = create_passive_peer(r, nw_addr);
        if (pp == NULL) {
            log_warn("io", L("Couldn't allocate passive-peer for %s:%s"), host_buff, port_buff);
            return 1;
        } else {
            if (batab_put(tab, pp, NULL) != 0) {
                log_warn("io", L("Couldn't add passive-peer %s:%s"), host_buff, port_buff);
                free_passive_peer(pp);
                return 1;
            }
            *do_free_addr_info = 0;
        }
    } else {
        log_info("io", L("passive peer entry for %s:%s already exists (ignoring)"), host_buff, port_buff);
    }
    return 0;
}

static void disconnect_and_discard_passive_peer(io_ctx_t *ctx, passive_peer_t *peer);
static void connect_and_add_passive_peer(io_ctx_t *ctx, passive_peer_t *peer);

static int reset_peers(io_ctx_t *ctx, const char* peer_file_path, int expected_port) {
    char peer[MAX_ADDR_LEN];
    char host_buff[MAX_ADDR_LEN];
    char port_buff[8];
    NET_ADDR(nw_addr);
    batab_t updated_passive_peers;

    if (batab_init(&updated_passive_peers, offsetof(passive_peer_t, addr), MAX_NW_ADDR_LEN, free_passive_peer, "current-passive-nw-addrs") != 0) {
        log_crit("io", L("failed to initialize current-passive-peers tracker"));
        return -1;
    }
    
    FILE *f = fopen(peer_file_path, "r");

    struct addrinfo hints, *res, *r, *p;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_buff, sizeof(port_buff), "%d", expected_port);

    int encountered_failure = 0;
    
    while (fgets(peer, MAX_ADDR_LEN, f) != NULL) {
        char *pos;
        if ((pos=strchr(peer, '\n')) != NULL)
            *pos = '\0';
        
        res = NULL;
        if (getaddrinfo(peer, port_buff, &hints, &res) != 0) {
            log_warn("io", L("ignoring peer: %s"), peer);
            continue;
        }
        log_info("io", L("processing peer: %s"), peer);

        r = res;
        p = NULL;
        int do_free_addr_info = 1;
        for (r = res; r != NULL; r = r->ai_next) {
            if (p != NULL) {
                p->ai_next = NULL;
                if (do_free_addr_info) {
                    freeaddrinfo(p);
                }
            }
            do_free_addr_info = 1;
            if (getnameinfo(r->ai_addr, r->ai_addrlen,
                            host_buff, sizeof(host_buff),
                            port_buff, sizeof(port_buff),
                            NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
                log_warn("io", L("failed to get name-info for peer: %s"), peer);
            }

            log_info("io", L("found peer: %s == host: %s and port: %s"), peer, host_buff, port_buff);

            memset(nw_addr, 0, MAX_NW_ADDR_LEN);
            switch (r->ai_family) {
            case AF_INET:
                if (ctx->using_af | USING_IPV4) {
                    void *client_addr = (void *)&((struct sockaddr_in *) r->ai_addr)->sin_addr.s_addr;
                    if (memcmp(client_addr, ctx->self_v4, IPv4_ADDR_LEN) > 0) {
                        log_info("io", L("peer %s is PASSIVE"), peer);
                        memcpy(nw_addr, client_addr, IPv4_ADDR_LEN);
                        encountered_failure |= capture_passive_peer(&updated_passive_peers, nw_addr, r, host_buff, port_buff, &do_free_addr_info);
                    }
                }
                break;
            case AF_INET6:
                if (ctx->using_af | USING_IPV6) {
                    void *client_addr = (void *)((struct sockaddr_in6 *) r->ai_addr)->sin6_addr.s6_addr;
                    if (memcmp(client_addr, ctx->self_v6, IPv6_ADDR_LEN) > 0) {
                        log_info("io", L("peer %s is PASSIVE"), peer);
                        memcpy(nw_addr, client_addr, IPv6_ADDR_LEN);
                        encountered_failure |= capture_passive_peer(&updated_passive_peers, nw_addr, r, host_buff, port_buff, &do_free_addr_info);
                    }
                }
                break;
            default:
                log_warn("io", L("Encountered unexpected address-family: %d"), r->ai_family);
            }
            p = r;
        }
        if (do_free_addr_info && p != NULL) freeaddrinfo(p);
    }

    if (! encountered_failure) {
        DBG("io", L("found a total of %u passive peers"), batab_sz(&updated_passive_peers));
        
        batab_entry_t *e;
        batab_foreach_do((&ctx->passive_peers), e) {
            passive_peer_t *old = (passive_peer_t*) e->value;
            passive_peer_t *corresponding_new = batab_get(&updated_passive_peers, old->addr);
            if (corresponding_new == NULL) {
                DBG("io", L("Killing (old) passive-peer: %s"), old->humanified_address);
                disconnect_and_discard_passive_peer(ctx, old);
            }
        }
        batab_foreach_do((&updated_passive_peers), e) {
            passive_peer_t *new = (passive_peer_t*) e->value;
            passive_peer_t *corresponding_old = batab_get(&ctx->passive_peers, new->addr);
            if (corresponding_old == NULL) {
                DBG("io", L("Attempting addition of passive-peer: %s"), new->humanified_address);
                connect_and_add_passive_peer(ctx, new);
            }
        }
    }

    batab_destory(&updated_passive_peers);

    fclose(f);

    return 0;
}

static void connect_and_add_passive_peer(io_ctx_t *ctx, passive_peer_t *peer) {
    assert(peer->addr_info != NULL);
    passive_peer_t *peer_copy = create_passive_peer(peer->addr_info, peer->addr);
    if (peer_copy == NULL) {
        log_warn("io", L("Failed to allocate passive-peer (copy) for address %s adding to io-ctx"), peer->humanified_address);
        return;
    }
    if (batab_put(&ctx->passive_peers, peer_copy, NULL) != 0) {
        log_warn("io", L("Failed to add passive-peer %s to io-ctx"), peer_copy->humanified_address);
        free(peer_copy);
        return;
    }

    assert(peer_copy->addr_info != NULL);
    peer->addr_info = NULL; /* so it doesn't get free'd */
    assert(peer_copy->addr_info != NULL);
    
    if (setup_outbound_connection(ctx, peer_copy) < 0) {
        log_warn("io", L("Failed to setup connection to peer: %s, adding disconnected"), peer_copy->humanified_address);
        LIST_INSERT_HEAD(&ctx->disconnected_passive_peers, peer_copy, link);
    }

    assert(peer_copy->addr_info != NULL);
}

static void disconnect_and_discard_passive_peer(io_ctx_t *ctx, passive_peer_t *peer) {
    io_sock_t *sock = batab_get(&ctx->live_conns, peer->addr);
    if (sock != NULL) destroy_sock(sock);
    passive_peer_t *pp = batab_get(&ctx->passive_peers, peer->addr);
    assert(pp != NULL);
    LIST_REMOVE(pp, link);
    assert(batab_remove(&ctx->passive_peers, peer->addr) == 0);
}

void trigger_peer_reset() {
    do_peer_reset = 1;
}

void trigger_io_loop_stop() {
    do_stop = 1;
}

static inline int do_accept(io_sock_t *listener_sock) {
    DBG("io", L("called to ACCEPT"));
    struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len = sizeof(remote_addr);
    NET_ADDR(nw_addr);
    int conn_fd = accept(listener_sock->fd, (struct sockaddr*) &remote_addr, &remote_addr_len);
    if (conn_fd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EMFILE) return 0;
        log_warn("io", L("failed to accept socket"));
    }
    memset(nw_addr, 0, MAX_NW_ADDR_LEN);
    void *client_addr;
    struct sockaddr *r = (struct sockaddr *) &remote_addr;
    switch (r->sa_family) {
    case AF_INET:
        client_addr = (void *)&((struct sockaddr_in *) r)->sin_addr.s_addr;
        memcpy(nw_addr, client_addr, IPv4_ADDR_LEN);
        break;
    case AF_INET6:
        client_addr = (void *)&((struct sockaddr_in6 *) r)->sin6_addr.s6_addr;
        memcpy(nw_addr, client_addr, IPv6_ADDR_LEN);
        break;
    default:
        log_warn("io", L("Encountered unexpected address-family: %d in inbound socket"), r->sa_family);
    }

    conn_sock_info_t addr_info = {.addr = nw_addr, .af = r->sa_family};
    if (add_sock(listener_sock->ctx, conn_fd, conn, init_conn_sock, &addr_info) != 0) {
        log_warn("io", L("Couldn't plug inbound socket into io-ctx"));
    }
    return 1;
}

#define CONN_IO_OK 0
#define CONN_IO_OK_EXHAUSTED 1
#define CONN_KILL -1
#define CONN_UNKNOWN_ERR -2
#define CONN_IO_OK_NOT_ENOUGH_SPACE -3

static inline int send_bl_batch(int fd, void *buff, ssize_t len, ssize_t *start, void *ignore, ssize_t ignore_) {
    ssize_t sent = send(fd, buff, len, MSG_NOSIGNAL);
    DBG("io", L("sent: %zd bytes to fd %d, wanted to send: %zd from %p"), sent, fd, len, buff);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            DBG("io", L("send failed as socket is not write-ready"));
            return CONN_IO_OK_EXHAUSTED;
        }
        if (errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE) {
            DBG("io", L("send failed as connection is broken"));
            return CONN_KILL;
        }
        return CONN_UNKNOWN_ERR;
    } else {
        *start += sent;
        return CONN_IO_OK;
    }
}

/* additional_len identifies additional-capacity available due to ring-buff wrap-around
   this is important for writes requiring atomicity semantics (its only a pessimistic promise
   for future io-handler call and should not be used immediately) */
typedef int (io_handler_fn_t)(int fd, void *buff, ssize_t len, ssize_t *tracker, void *hdlr_ctx, ssize_t additional_len);

#define BUFF_STATE_FORAMT_STR "ring: %p { sz=%zd, start=%zd, end=%zd, wrapped=%d }"

#define BUFF_STATE_VARS(r)                      \
    r, r->sz, r->start, r->end, r->wraped

static inline int drain_ring(int fd, ring_buff_t *r, io_handler_fn_t *io_hdlr, void *hdlr_ctx) {
    DBG("io", L("fd %d, "BUFF_STATE_FORAMT_STR", io_hdlr: %p, ctx: %p"), fd, BUFF_STATE_VARS(r), io_hdlr, hdlr_ctx);

    int ret = CONN_IO_OK;
    do {
        if (r->wraped) {
            DBG("io", L("wrapped"));
            if (r->sz == r->start) {
                DBG("io", L("resetting start as tail drained out"));
                r->start = 0;
                r->wraped = 0;
                continue;
            }
            ssize_t len = r->sz - r->start;
            ssize_t additional_len = r->end;
            DBG("io", L("calling io-hdlr while wrapped, space-advertized %zd, additional %zd, buff-start-offset: %zd (buff_base: %p) "BUFF_STATE_FORAMT_STR), len, additional_len, (ssize_t) r->buff + r->start, r->buff, BUFF_STATE_VARS(r));
            ret = io_hdlr(fd, r->buff + r->start, len, &r->start, hdlr_ctx, additional_len);
            DBG("io", L("after io-hdlr call(ret: %d): "BUFF_STATE_FORAMT_STR), ret, BUFF_STATE_VARS(r));
        } else {
            DBG("io", L("NOT wrapped"));
            if (r->end == r->start) {
                DBG("io", L("ring is empty, breaking"));
                break;
            }
            ssize_t len = r->end - r->start;
            ssize_t additional_len = 0;
            DBG("io", L("calling io-hdlr while wrapped, space-advertized %zd, additional %zd, buff-start-offset: %zd (buff_base: %p)"BUFF_STATE_FORAMT_STR), len, additional_len, (ssize_t) r->buff + r->start, r->buff, BUFF_STATE_VARS(r));
            ret = io_hdlr(fd, r->buff + r->start, len, &r->start, hdlr_ctx, additional_len);
            DBG("io", L("after io-hdlr call(ret: %d): "BUFF_STATE_FORAMT_STR), ret, BUFF_STATE_VARS(r));
        }
        DBG("io", L("ret: %d, ring: %p { sz=%zd, start=%zd, end=%zd, wrapped=%d }"), ret, r, r->sz, r->start, r->end, r->wraped);
    } while(CONN_IO_OK == ret);
    return ret;
}

static inline int recv_batch(int fd, void *buff, ssize_t max_sz, ssize_t *end, void *ignore, ssize_t ignore_) {
    ssize_t rcvd = recv(fd, buff, max_sz, 0);
    DBG("io", L("rcvd: %zd bytes from fd %d, wanted to recv upto: %zd into %p"), rcvd, fd, max_sz, buff);
    if (rcvd == 0) {
        DBG("io", L("Peer closed the connection, closing it now"));
        return CONN_KILL;
    }
    if (rcvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            DBG("io", L("recv failed as socket is not read-ready"));
            return CONN_IO_OK_EXHAUSTED;
        }
        if (errno == ECONNREFUSED || errno == ENOTCONN) {
            DBG("io", L("recv failed as connection is broken"));
            return CONN_KILL;
        }
        DBG("io", L("recv failed due to some unknown error: %d"), errno);
        return CONN_UNKNOWN_ERR;
    } else {
        *end += rcvd;
        return CONN_IO_OK;
    }
}

typedef ssize_t (data_push_fn_t)(void *b1, ssize_t len1, void *b2, ssize_t len2, void *hdlr_ctx);

static inline int fill_ring(int fd, ring_buff_t *r, io_handler_fn_t *io_hdlr, data_push_fn_t *data_pusher, void *hdlr_ctx) {
    DBG("io", L("fd %d, "BUFF_STATE_FORAMT_STR", io_hdlr: %p, data_pusher: %p, ctx: %p"), fd, BUFF_STATE_VARS(r), io_hdlr, data_pusher, hdlr_ctx);
    int ret = CONN_IO_OK;
    int full = 0;
    do {
        if (r->wraped) {
            DBG("io", L("wrapped"));
            if (r->start == r->end) {
                DBG("io", L("Buffer full, not calling io-handler"));
                full = 1;
            } else {
                DBG("io", L("before io-hdlr call "BUFF_STATE_FORAMT_STR), BUFF_STATE_VARS(r));
                ret = io_hdlr(fd, r->buff + r->end, r->start - r->end, &r->end, hdlr_ctx, 0);
                DBG("io", L("after io-hdlr call(ret: %d) "BUFF_STATE_FORAMT_STR), ret, BUFF_STATE_VARS(r));
            }
        } else {
            if (r->sz == r->end) {
                DBG("io", L("Fill-area reached end-of-buffer, wrapping"));
                r->end = 0;
                r->wraped = 1;
                continue;
            }
            DBG("io", L("before io-hdlr call "BUFF_STATE_FORAMT_STR), BUFF_STATE_VARS(r));
            ret = io_hdlr(fd, r->buff + r->end, r->sz - r->end, &r->end, hdlr_ctx, r->start);
            DBG("io", L("after io-hdlr call(ret: %d) "BUFF_STATE_FORAMT_STR), ret, BUFF_STATE_VARS(r));
        }
        /* try to push data, fakers like write-to-tun don't provide this, hence nullable */
        if (data_pusher != NULL) {
            if (r->wraped) {
                ssize_t len1 = r->sz - r->start;
                ssize_t len2 = r->end;
                int called = 0;
                ssize_t moved = 0;
                if ((len1 + len2) > 0) {
                    if (len1 == 0) {
                        moved = data_pusher(r->buff, len2, NULL, 0, hdlr_ctx);
                    } else {
                        moved = data_pusher(r->buff + r->start, len1, r->buff, len2, hdlr_ctx);
                    }
                    called = 1;
                    if (moved > 0) {
                        full = 0;
                        if (moved > len1) {
                            r->start = moved - len1;
                            r->wraped = 0;
                        } else {
                            r->start += moved;
                        }
                    }
                }
                DBG("io", L("data-pusher called(%d) (with wrapped buff) with len1: %zd and len2: %zd and moved: %zd "BUFF_STATE_FORAMT_STR), called, len1, len2, moved, BUFF_STATE_VARS(r));
            } else {
                ssize_t len1 = r->end - r->start;
                ssize_t moved = 0;
                int called = 0;
                if (len1 > 0) {
                    called = 1;
                    moved = data_pusher(r->buff + r->start, len1, NULL, 0, hdlr_ctx);
                }
                if (moved > 0) {
                    full = 0;
                    r->start += moved;
                }
                DBG("io", L("data-pusher called(%d) with len1: %zd and moved: %zd "BUFF_STATE_FORAMT_STR), called, len1, moved, BUFF_STATE_VARS(r));
            }
        }
    } while((CONN_IO_OK == ret) || full);
    DBG("io", L("return: %d"), ret);
    return ret;
}

static inline int ring_empty(ring_buff_t *r) {
    return (! r->wraped) && (r->start == r->end);
}

struct tun_tx_s {
    ring_buff_t *backlog;
    int fd;
};

typedef struct tun_tx_s tun_tx_t;

struct tun_write_buff_s {
    void *b1, *b2;
    ssize_t len1, len2;
};

typedef struct tun_write_buff_s tun_write_buff_t;

static inline ssize_t playback_tun_write_single_src_buf(void *playback_target_buff, ssize_t *max_playback_len, ssize_t *actual_playback_len, void *src_buf, ssize_t *src_len) {
    ssize_t write_sz = (*max_playback_len >= *src_len) ? *src_len : *max_playback_len;
    if (write_sz > 0) {
        memcpy(playback_target_buff, src_buf, write_sz);
        *actual_playback_len += write_sz;
        *src_len -= write_sz;
        *max_playback_len -= write_sz;
    }
    return write_sz;
}

static int playback_tun_write_buf(int ignore_fd, void *playback_target_buff, ssize_t max_playback_len, ssize_t *actual_playback_len, void *opaq_tun_write_buff, ssize_t promised_future_playback_len) {
    tun_write_buff_t *b = (tun_write_buff_t *) opaq_tun_write_buff;
    if ((b->len1 + b->len2) > (max_playback_len + promised_future_playback_len)) return CONN_IO_OK_EXHAUSTED; /* because we don't want half-written packets */
    if (b->len1 > 0) {
        playback_tun_write_single_src_buf(playback_target_buff, &max_playback_len, actual_playback_len, b->b1, &b->len1);
        if (b->len1 > 0) return CONN_IO_OK;
    }
    if (b->len2 > 0) {
        playback_tun_write_single_src_buf(playback_target_buff, &max_playback_len, actual_playback_len, b->b2, &b->len2);
        if (b->len2 > 0) return CONN_IO_OK;
    }
    return CONN_IO_OK_EXHAUSTED;
}

static inline ssize_t push_pkt_to_tun_backlog_ring(tun_tx_t *tun_tx, void *b1, ssize_t len1, void *b2, ssize_t len2, int *full) {
    tun_write_buff_t tun_write_buf = {.b1 = b1, .len1 = len1, .b2 = b2, .len2 = len2};
    fill_ring(-1, tun_tx->backlog, playback_tun_write_buf, NULL, &tun_write_buf);
    ssize_t total = len1 + len2;
    ssize_t remaining = tun_write_buf.len1 + tun_write_buf.len2;
    if (remaining != 0) {
        *full = 1;
        assert(remaining == total);
        return 0;
    }
    return total;
}

static inline ssize_t push_pkt_to_tun_or_ring(tun_tx_t *tun_tx, void *b1, ssize_t len1, void *b2, ssize_t len2, int *full) {
    if (ring_empty(tun_tx->backlog)) {
        struct iovec out[2] = {{.iov_base = b1, .iov_len = len1}, {.iov_base = b2, .iov_len = len2}};
        ssize_t written = writev(tun_tx->fd, out, 2);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return push_pkt_to_tun_backlog_ring(tun_tx, b1, len1, b2, len2, full);
            }
            log_warn("io", L("Failed to write to tun %zd and %zd bytes from buff %p and %p"), len1, len2, b1, b2);
            return 0;
        } else {
            assert(written == len1 + len2);
            return written;
        }
    } else {
        return push_pkt_to_tun_backlog_ring(tun_tx, b1, len1, b2, len2, full);
    }
}

static inline ssize_t push_to_tun_ipv4(tun_tx_t *tun_tx, void *b1, ssize_t len1, void *b2, ssize_t len2) {
    assert(len1 > 0);

    ssize_t overall_pushed = 0;

    int full = 0;

    do {
        uint16_t pkt_len = parse_ipv4_pkt_sz(b1, len1, b2, len2);
        DBG("io", L("Overall pushed: %zd till now, this pkg_len: %hu, len1: %zd, len2: %zd (buffers: 1: %p and 2: %p)"), overall_pushed, pkt_len, len1, len2, b1, b2);
        if ((pkt_len == 0) || ((len1 + len2) < pkt_len)) {
            DBG("io", L("Postponing push to tun, not enough data. Overall pushed till return: %zd"), overall_pushed);
            return overall_pushed;
        }

        ssize_t pushed;
        if (len1 >= pkt_len) {
            pushed = push_pkt_to_tun_or_ring(tun_tx, b1, pkt_len, NULL, 0, &full);
            len1 -= pushed;
            b1 += pushed;
            DBG("io", L("First buff had sufficient data to complete packet. Pushed: %zd"), pushed);
        } else {
            ssize_t buf2_to_be_pushed = (pkt_len - len1);
            assert((len2 - buf2_to_be_pushed) >= 0);
            pushed = push_pkt_to_tun_or_ring(tun_tx, b1, len1, b2, buf2_to_be_pushed, &full);
            if (pushed > 0) {
                len1 = 0;
                len2 -= buf2_to_be_pushed;
                b2 += buf2_to_be_pushed;
            }
            DBG("io", L("First buff didn't have sufficient data to complete packet. Pushed: %zd (remaining now: len1: %zd, len2: %zd)"), pushed, len1, len2);
        }
        overall_pushed += pushed;
        DBG("io", L("Overall pushed till now: %zd, full: %d"), overall_pushed, full);
    } while(! full);

    return overall_pushed;
}

static inline ssize_t push_to_tun_ipv6(tun_tx_t *tun_tx, void *b1, ssize_t len1, void *b2, ssize_t len2) {
    log_crit("log", L("IPv6 packet-hanlding not implemented yet"));
    return 0;
}

static ssize_t push_to_tun(void *b1, ssize_t len1, void *b2, ssize_t len2, void *hdlr_ctx) {
    assert(hdlr_ctx != NULL);
    tun_tx_t *tun_tx = (tun_tx_t *) hdlr_ctx;
    DBG("io", L("buff1: %p, len1: %zd, buff2: %p, len2: %zd"), b1, len1, b2, len2);
    uint8_t octate_1;
    assert(len1 + len2 > 0);
    if (len1 > 0) {
        octate_1 = *(uint8_t *)b1;
    } else {
        octate_1 = *(uint8_t *)b2;
    }
    ssize_t pushed = 0;
    switch (octate_1 & 0xF0) {
    case 0x40:
        pushed = push_to_tun_ipv4(tun_tx, len1 > 0 ? b1 : b2, len1 > 0 ? len1 : len2, len1 > 0 ? b2 : NULL, len1 > 0 ? len2 : 0);
        DBG("io", L("IPv4, pushed: %zd"), pushed);
        break;
    case 0x60:
        pushed = push_to_tun_ipv6(tun_tx, len1 > 0 ? b1 : b2, len1 > 0 ? len1 : len2, len1 > 0 ? b2 : NULL, len1 > 0 ? len2 : 0);
        DBG("io", L("IPv6, pushed: %zd"), pushed);
        break;
    default:
        log_crit("io", L("encountered an unknown packet-type (L3 protocol version: %d), won't handle, will let backlog build"), octate_1 >> 4);
    }
    return pushed;
}

static inline void conn_io(uint32_t event, io_sock_t *conn) {
    if (event | EPOLLOUT) {
        DBG("io", L("called for %d OUT"), conn->fd);
        if (CONN_KILL == drain_ring(conn->fd, &conn->d.conn.tx, send_bl_batch, NULL)) {
            log_warn("io", L("Send failed, connection is being dropped for sock: %d"), conn->fd); 
            destroy_sock(conn);
        }
    }
    if (event | EPOLLIN) {
        DBG("io", L("called for %d IN"), conn->fd);
        tun_tx_t tun_tx;
        tun_tx.fd = conn->ctx->tun_fd;
        tun_tx.backlog = conn->ctx->tun_tx;
        if (CONN_KILL == fill_ring(conn->fd, &conn->d.conn.rx, recv_batch, push_to_tun, &tun_tx)) {
            log_warn("io", L("Recv failed, connection id being dropped for sock: %d"), conn->fd);
            destroy_sock(conn);
        }
    }
}

static inline int expand_tun_wbuff_if_necessary(tun_pkt_buff_t *wbuff, ssize_t additional_space_required) {
    if (additional_space_required > (wbuff->capacity - wbuff->len)) {
        ssize_t new_cap = wbuff->capacity * 2;
        if (new_cap < (additional_space_required + wbuff->len)) {
            new_cap = additional_space_required + wbuff->len;
        }
        void *expanded_buff = realloc(wbuff->buff, new_cap);
        if (NULL == expanded_buff) {
            log_crit("io", L("failed to expand tun-write pkt-buff, was trying allocation sz: %zd"), new_cap);
            return -1;
        }
        wbuff->buff = expanded_buff;
        wbuff->capacity = new_cap;
    }
    return 0;
}

static inline int write_to_tun(int fd, void *buff, ssize_t len, ssize_t *start, void *_tun_write_buff, ssize_t additional_len) {
    tun_pkt_buff_t *wbuff = (tun_pkt_buff_t *) _tun_write_buff;
    int ret = CONN_IO_OK;
    uint16_t pkt_len;

    do {
        ssize_t written = 0;
        if (wbuff->current_pkt_len == 0) { /* start of a new pkt */
            pkt_len = parse_ipv4_pkt_sz(buff, len, NULL, 0);
            if (pkt_len > 0) {
                if (pkt_len <= len) {
                    written = write(fd, buff, pkt_len);
                    if (written > 0) {
                        assert(written == pkt_len);
                        buff += written;
                        len -= written;
                    }
                } else {
                    if (expand_tun_wbuff_if_necessary(wbuff, pkt_len) != 0) return CONN_UNKNOWN_ERR;
                    wbuff->current_pkt_len = pkt_len;
                    memcpy(wbuff->buff, buff, len);
                    wbuff->len += len;
                    len = 0;
                }
            }
        } else {
            ssize_t deficit = wbuff->current_pkt_len - wbuff->len;
            if (len >= deficit) {
                struct iovec out[2] = {{.iov_base = wbuff->buff, .iov_len = wbuff->len}, {.iov_base = buff, .iov_len = deficit}};
                written = writev(fd, out, 2);
                if (written > 0) {
                    assert(written == (wbuff->len + deficit));
                    buff += deficit;
                    len -= deficit;
                    wbuff->len = 0;
                    wbuff->current_pkt_len = 0;
                }
            } else {
                memcpy(wbuff->buff + wbuff->len, buff, len);
                wbuff->len += len;
                len = 0;
            }
        }

        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ret = CONN_IO_OK_EXHAUSTED;
            } else {
                log_crit("io", L("failed to write to tun dev"));
                ret = CONN_UNKNOWN_ERR;
            }
        }
    } while((ret == CONN_IO_OK) && (len > 0) && (pkt_len > 0));

    return ret;
}

struct conn_bound_pkt_s {
    tun_pkt_buff_t *pkt_buff;
    int dest_fd;
    ssize_t already_written;
};

typedef struct conn_bound_pkt_s conn_bound_pkt_t;

static int read_from_tun_buff(int fd, void *to_buff, ssize_t capacity, ssize_t *end, void *hdlr_ctx, ssize_t additional_capacity) {
    conn_bound_pkt_t *pkt = (conn_bound_pkt_t *) hdlr_ctx;
    ssize_t available_content = pkt->pkt_buff->len - pkt->already_written;
    ssize_t to_write = (available_content > capacity) ? capacity : available_content;

    if (pkt->already_written == 0) { /* first invocation */
        if (pkt->pkt_buff->len > (to_write + additional_capacity)) {
            return CONN_IO_OK_NOT_ENOUGH_SPACE;
        }
    }

    memcpy(to_buff, pkt->pkt_buff->buff + pkt->already_written, to_write);
    *end += to_write;
    pkt->already_written += to_write;
    return (pkt->already_written == pkt->pkt_buff->len) ? CONN_IO_OK_EXHAUSTED : CONN_IO_OK;
}

static ssize_t write_passthru_to_conn(void *b1, ssize_t len1, void *b2, ssize_t len2, void *hdlr_ctx) {
    assert(hdlr_ctx != NULL);
    conn_bound_pkt_t *pkt = (conn_bound_pkt_t *) hdlr_ctx;
    int dest_fd = pkt->dest_fd;
    assert(dest_fd > 0);
    DBG("io", L("dest_fd: %d, buff1: %p, len1: %zd, buff2: %p, len2: %zd"), dest_fd, b1, len1, b2, len2);
    ssize_t written = 0;
    if (len1 > 0) {
        send_bl_batch(dest_fd, b1, len1, &written, NULL, 0);
    }
    if ((written == len1) && len2 > 0) {
        send_bl_batch(dest_fd, b2, len2, &written, NULL, 0);
    }
    DBG("io", L("wrote %zd bytes to sock: %d"), written, dest_fd);
    return written;
}

static inline void write_to_conn(io_ctx_t *ctx, io_sock_t *conn, tun_pkt_buff_t *pkt_buff) {
    if (conn == NULL) {
        DBG("io", L("trying to write to unknown connection, dropping packet"));
        ctx->c_world_tx.drop_p++;
        ctx->c_world_tx.drop_b += pkt_buff->len;
        return;
    }

    conn_bound_pkt_t pkt = {pkt_buff, conn->fd, 0};

    int ret = fill_ring(-1, &conn->d.conn.tx, read_from_tun_buff, write_passthru_to_conn, &pkt);
    
    if (CONN_IO_OK_NOT_ENOUGH_SPACE == ret) {
        DBG("io", L("ring full, dropping packet"));
        ctx->c_world_tx.drop_p++;
        ctx->c_world_tx.drop_b += pkt_buff->len;
        return;
    }

    assert(ret == CONN_IO_OK_EXHAUSTED);
}

static inline void read_tun_and_xmit(io_sock_t *tun) {
    int fd = tun->fd;
    io_ctx_t *ctx = tun->ctx;
    tun_pkt_buff_t *pkt_buff = &tun->d.tun.r_buff;
    NET_ADDR(nw_addr);
    uint8_t prev_ip_v = 0xF0;
    uint32_t *nw_addr_ipv4 = (uint32_t *) nw_addr;

    do {
        pkt_buff->len = read(fd, pkt_buff->buff, pkt_buff->capacity);
        DBG("io", L("read %zd bytes from tun"), pkt_buff->len);
        if (pkt_buff->len <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_crit("io", L("Unexpected error in tun-read"));
            break;
        }
        uint8_t ip_v = (*(uint8_t *) pkt_buff->buff) & 0xF0;
        if (ip_v < prev_ip_v) {
            memset(nw_addr, 0, MAX_NW_ADDR_LEN);
            prev_ip_v = ip_v;
        }
        switch(ip_v) {
        case 0x40:
            assert(pkt_buff->len > 20);
            *nw_addr_ipv4 = *(((uint32_t *) pkt_buff->buff) + 4);
            io_sock_t *dest_sock = batab_get(&ctx->live_conns, nw_addr);
            write_to_conn(ctx, dest_sock, pkt_buff);
            break;
        case 0x60: /* implement me! */
        default:
            log_crit("io", L("Unknown IP version: %d"), ip_v);
        }
    } while (1);
}

static inline void tun_io(uint32_t event, io_sock_t *tun) {
    if (event | EPOLLOUT) {
        DBG("io", L("called for %d OUT"), tun->fd);
        if (CONN_UNKNOWN_ERR == drain_ring(tun->fd, &tun->d.tun.tx, write_to_tun, &tun->d.tun.w_buff))
            log_warn("io", L("TUN write failed. Fd: %d"), tun->fd); 
    }
    if (event | EPOLLIN) {
        DBG("io", L("called for %d IN"), tun->fd);
        read_tun_and_xmit(tun);
    }
}

static inline void handle_io_evt(uint32_t event, io_sock_t *sock) {
    if (sock->typ == tun) {
        tun_io(event, sock);
    } else if (sock->typ == conn) {
        conn_io(event, sock);
    } else {
        assert(sock->typ == lstn);
        while(do_accept(sock));
    }
}

#ifndef LIST_FIRST
#define	LIST_FIRST(head)		((head)->lh_first)
#endif

#ifndef LIST_NEXT
#define	LIST_NEXT(elm, field)		((elm)->field.le_next)
#endif

static void fix_broken_connections(io_ctx_t *ctx) {
    int success, total;
    success = total = 0;
    passive_peer_t *peer, *prev_peer;
    int do_remove = 0;
    for (peer = LIST_FIRST(&ctx->disconnected_passive_peers);
         NULL != peer;
         prev_peer = peer, peer = LIST_NEXT(peer, link)) {
        assert(peer->addr_info != NULL);
        if (do_remove) {
            LIST_REMOVE(prev_peer, link);
            do_remove = 0;
        }
        total++;
        int fd = setup_outbound_connection(ctx, peer);
        if (fd > 0) {
            log_info("io", L("Re-connect to peer %s succesful, fd: %d"), peer->humanified_address, fd);
            do_remove = 1;
            success++;
        } else {
            log_info("io", L("Failed to connect to peer %s"), peer->humanified_address);
        }
    }
    if (do_remove) {
        LIST_REMOVE(prev_peer, link);
    }
    log_warn("io", L("Recconnect attempt summary: %d of %d passive-peers re-connected successfully"), success, total);
}

#define MAX_POLLED_EVENTS 256

int io(int tun_fd, const char* peer_file_path, const char *self_addr_v4, const char *self_addr_v6, int listener_port, const char *ipset_name, int try_reconnect_itvl) {
    int ret = -1;
    io_ctx_t *ctx;
    time_t last_reconnect_at = time(NULL);
    if ((ctx = init_io_ctx(tun_fd, self_addr_v4, self_addr_v6, ipset_name)) != NULL) {
        if (setup_listener(ctx, listener_port) == 0) {
            trigger_peer_reset();
            int num_evts;
            struct epoll_event evts[MAX_POLLED_EVENTS];
            while ( ! do_stop) {
                num_evts = epoll_wait(ctx->epoll_fd, evts, MAX_POLLED_EVENTS, try_reconnect_itvl * 1000); /* timeout is ms */
                if (num_evts < 0) {
                    log_warn("io", L("io-poll failed"));
                } else {
                    for (int i = 0; i < num_evts; i++) {
                        handle_io_evt(evts[i].events, (io_sock_t *) evts[i].data.ptr);
                    }
                }
                if (do_peer_reset) {
                    reset_peers(ctx, peer_file_path, listener_port);
                    do_peer_reset = 0;
                }
                time_t now = time(NULL);
                if ((now - last_reconnect_at) > try_reconnect_itvl) {
                    fix_broken_connections(ctx);
                    last_reconnect_at = now;
                }
            }
            ret = 0;
        }
    }
    destroy_io_ctx(ctx);
    return ret;
}
