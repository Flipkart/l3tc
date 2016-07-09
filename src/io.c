#include <stdio.h>

#include "io.h"
#include "common.h"

#define LISTEN_BACKLOG 1024
#define INET_ADDR_STRING_LEN 48;

#define IPv4_ADDR_LEN sizeof(((struct in_addr *)0)->s_addr)
#define IPv6_ADDR_LEN sizeof(((struct in6_addr *)0)->s6_addr)

#define MAX_NW_ADDR_LEN ((IPv6_ADDR_LEN > IPv4_ADDR_LEN) ? IPv6_ADDR_LEN : IPv4_ADDR_LEN)

#define TUN_RING_SZ 4*1024*1024; /* 4 MB */
#define CONN_RING_SZ 16*1024; /* 16 KB */

typedef struct io_ctx_s io_ctx_t;
typedef struct io_sock_s io_sock_t;

typedef struct ring_buff_s ring_buff_t;

struct ring_buff_s {
    void *buff;
    size_t sz, start, end;
    int drained;
};

struct io_sock_s {
    LIST_ENTRY(io_req_s) link;
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
            int outbound;
            ring_buff_t rx_bl, tx_bl;
        } conn;
        struct {
            ring_buff_t tx_bl;
        } tun;
    } d;
};

struct passive_peer_s {
    LIST_ENTRY(passive_peer_s) link;
    struct addrinfo *addr_info;    
    NET_ADDR(addr);
    char humanified_address[INET_ADDR_STRING_LEN];
};

typedef struct passive_peer_s passive_peer_t;

#define USING_IPV4 0x1
#define USING_IPV6 0x2

#define NET_ADDR(field_name)                    \
    uint8_t field_name[MAX_NW_ADDR_LEN]

struct io_ctx_s {
    LIST_HEAD(all, io_sock_s) all_sockets;
    batab_t live_sockets; /* to passive and active peers */
    LIST_HEAD(dpp, passive_peer_s) disconnected_passive_peers;
    batab_t passive_peers;
    int tun_fd;
    int epoll_fd;
    NET_ADDR(self_v4);
    NET_ADDR(self_v6);
    int using_af;
};

static inline void destroy_ring_buff(ring_buff_t *ring) {
    free(ring->buff);
}

static inline void destroy_sock(io_sock_t *sock) {
    if (NULL == sock) return;
    log_debug("io", L("destroying socket of type: %d (fd: %d)"), sock->typ, sock->fd);

    if (conn == sock->typ) {
        drop_conn_route(sock);
    }
    
    if (epoll_ctl(sock->ctx, EPOLL_CTL_DEL, sock->fd, NULL)) {
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

    LIST_REMOVE(sock, link);

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
            free(sock);
            close(fd);
            return -1;
        }
    }

    sock->evt.events = EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLET;
    sock->evt.data.ptr = sock;
    
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sock->fd, sock->evt) != 0) {
        log_warn("io", L("failed to add fd to polling context"));
        destroy_sock(sock);
        return -1;
    }

    LIST_INSERT_HEAD(&ctx->all_sockets, sock, link);

    if (sock->typ == conn) {
        setup_conn_route(sock);
    }

    return 0;
}

static inline int init_backlog_ring(ring_buff_t *rbuff, size_t sz) {
    if (NULL == (rbuff->buff = malloc(sz))) {
        return -1;
    }
    rbuff->sz = sz;
    rbuff->start = rbuff->end = 0;
}

static int init_tun_tx_backlog_ring(io_sock_t *sock, void *ign) {
    if (init_backlog_ring(&sock->d.tun.tx_bl, TUN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate tx-backlog ring for tun"));
        return -1;
    }
    return 0;
}

static io_ctx_t * init_io_ctx(int tun_fd, const char *self_addr_v4, const char *self_addr_v6) {
    int epoll_fd;
    
#	if defined(EPOLL_CLOEXEC) && defined(HAVE_EPOLL_CREATE1)
	log_debug("io", L("using epoll_create1"));
	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if((epollfd < 0) && (ENOSYS == errno))
#	endif
	{
		log_warn("io", L("uses epoll_create"));
		/* Just provide some number, kernel ignores it anyway */
		epollfd = epoll_create(10);
	}

    if (epollfd < 0) {
        log_warn("io", L("Could not create epoll-ctx"));
        return NULL;
    }

    io_ctx_t *ctx = calloc(1, sizeof(io_ctx_t));
    if (NULL == ctx) {
        log_warn("io", L("Could not allocate mem for ctx"));
        close(epollfd);
        return NULL;
    }

    ctx->epoll_fd = epollfd;
    ctx->tun_fd = tun_fd;
    LIST_INIT(ctx->disconnected_passive_peers);
    LIST_INIT(ctx->all_sockets);
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
    if (batab_init(&ctx->passive_peers, offsetof(passive_peer_t, addr), MAX_NW_ADDR_LEN, destruct_passive_peer, "passive-peers") != 0) {
        log_crit("io", L("Couldn't initialize passive-peers map"));
        destroy_io_ctx(ctx);
        return null;
    }
    if (batab_init(&ctx->live_sockets, offsetof(io_sock_t, d.conn.peer), MAX_NW_ADDR_LEN, NULL, "live-conn") != 0) {
        log_crit("io", L("Couldn't initialize live-sockets map"));
        destroy_io_ctx(ctx);
        return null;
    }
    if (add_sock(ctx, tun_fd, tun, init_tun_tx_backlog_ring, NULL) != 0) {
        log_crit("io", L("Couldn't add tun to io-ctx"));
    }
    return ctx;
}

static void destroy_io_ctx(io_ctx_t *ctx) {
    batab_destory(&ctx->live_sockets);
    io_sock_t *s, *tmp;
    LIST_FOREACH_SAFE(s, &ctx->all_sockets, link, tmp) {
        destroy_sock(s);
    }
    batab_destory(&ctx->passive_peers);
}

static inline void setup_conn_route(io_sock_t *sock) {
    
}

static inline void drop_conn_route(io_sock_t *sock) {

}

static inline void destroy_conn_sock_data(io_sock_t *sock) {
    io_ctx_t *ctx = sock->ctx;
    assert(sock->typ == conn);
    if (sock->fd >= 0) {
        assert(batab_remove(&ctx->live_sockets, &sock->d.conn.peer) == 0);
        if (sock->d.conn.outbound) {
            passive_peer_t *pp = batab_get(&ctx->passive_peers, addr);
            assert(pp != NULL);
            LIST_INSERT_HEAD(&ctx->disconnected_passive_peers, pp, link);
        }
    }
    destroy_ring_buff(&sock->d.conn.tx_bl);
    destroy_ring_buff(&sock->d.conn.rx_bl);
}

static inline void destroy_tun_sock_data(io_sock_t *sock) {
    destroy_ring_buff(&sock->d.tun.tx_bl);
}

static int setup_listener(io_ctx_t *ctx, int listener_port) {
    char buff[8];
    struct addrinfo hints, *res = NULL, *r;
    int max_socks, num_socks;
    memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    snprintf(buff, sizeof(buff), "%d", listener_port);
    getaddrinfo("", buff, &hints, &res);
    
    for (max_socks = 0, num_socks = 0, r = res;
         r != NULL;
         r = r->ai_next, max_socks++) {
        
		sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (sock < 0) {
            log_warn("io", L("error in creating tcp listening socket"));
            continue;
		}

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
			log_warn("io", L("setting reuse-addr failed"));
            close(sock);
			continue;
		}

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
        log_warn("io", L("Listening to %d sockets, which is less than expected %d", num_socks, max_socks));
    }

    if (num_socks == 0) {
        log_warn("io", L("Failed to setup listener, none of expected %d sockets initialized correctly.", max_socks));
        return -1;
    }

    return 0;
}

static int do_peer_reset = 0;
static int do_stop = 0;

static int setup_outbount_connection(passive_peer_t *peer) {
    struct addrinfo *r = peer->addr_info;
    int c_fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    if (c_fd < 0) {
        log_warn("io", L("could not create socket for connecting to peer: %s"), peer);
    } else {
        if (connect(c_fd, r->ai_addr, r->ai_addrlen) == 0) {
            log_info("io", L("connnected as client to peer: %s"), peer);
        } else {
            log_warn("io", L("failed to setup state for connection to peer: %s [%s:%s], will try later"), peer, host_buff, port_buff);
            close(c_fd);
            return -1;
        }
    }
    return c_fd;
}

static inline passive_peer_t *create_passive_peer(struct addrinfo *r, uint8_t *nw_addr) {
    passive_peer_t *pp = malloc(sizeof(passive_peer_t));
    if (pp == NULL) return NULL;
    pp->addr_info = r;
    memcpy(pp->addr, nw_addr, MAX_NW_ADDR_LEN);
    if (inet_ntop(pp->addr_info->ai_family, pp->addr, pp->humanified_address, INET_ADDR_STRING_LEN) == NULL) {
        log_warn("io", L("Failed to copy human-readable addr for endpoint"));
    }
    return pp;
}

int capture_passive_peer(batab_t *tab, uint8_t *nw_addr, struct addrinfo *r, const char *host_buff, const char *port_buff, int **do_free_addr_info) {
    if (batab_get(tab, nw_addr) == NULL) {
        passive_peer_t *pp = create_passive_peer(r, nw_addr);
        if (pp == NULL) {
            log_warn("io", L("Couldn't allocate passive-peer for %s:%s"), host_buff, port_buff);
            return 1;
        } else {
            if (batab_put(tab, pp, NULL) != 0) {
                log_warn("io", L("Couldn't add passive-peer %s:%s"), host_buff, port_buff);
                destroy_passive_peer(pp);
                return 1;
            }
            *do_free_addr_info = 0;
        }
    }
    return 0;
}

static int reset_peers(io_ctx_t *ctx, const char* peer_file_path, const char* self_addr, int expected_port) {
    char peer[MAX_ADDR_LEN];
    char host_buff[MAX_ADDR_LEN];
    char port_buff[8];
    NET_ADDR(nw_addr);
    batab_t updated_passive_peers;

    if (batab_init(&current_passive_peers, 0, MAX_NW_ADDR_LEN, free, "current-passive-nw-addrs") != 0) {
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
    
    while (fgets(peer, MAX_HOST_LEN, f) != NULL) {
        res = NULL
        if (getaddrinfo(peer, port_buff, &hints, &res) != 0) {
            log_warn("io", L("ignoring peer: %s"), peer);
            continue;
        }

        r = res;
        p = NULL;
        for (r = res; r != NULL; r = r->ai_next, i++) {
            if (p != NULL) {
                p->ai_next = NULL;
                if (do_free_addr_info) {
                    freeaddrinfo(p);
                }
            }
            int do_free_addr_info = 1;
            if (getnameinfo(r->ai_addr, r->ai_addrlen,
                            host_buf, sizeof(host_buf),
                            port_buf, sizeof(port_buf),
                            NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
                log_warn("io", L("failed to get name-info for peer: %s"), peer);
            }

            memset(nw_addr, 0, MAX_NW_ADDR_LEN);
            switch (r->ai_family) {
            case AF_INET:
                if (ctx->using_af | USING_IPV4) {
                    void *client_addr = (void *)&((struct sockaddr_in *) r->ai_addr)->sin_addr;
                    if (memcmp(client_addr, ctx->self_v4, IPv4_ADDR_LEN) > 0) {
                        memcpy(nw_addr, client_addr, IPv4_ADDR_LEN);
                        encountered_failure = capture_passive_peer(&updated_passive_peers, nw_addr, r, host_buff, port_buff, &do_free_addr_info);
                    }
                }
                break;
            case AF_INET6:
                if (ctx->using_af | USING_IPV6) {
                    void *client_addr = (void *)&((struct sockaddr_in6 *) r->sin6_addr)->s6_addr;
                    if (memcmp(client_addr, ctx->self_v6, IPv6_ADDR_LEN) > 0) {
                        memcpy(nw_addr, client_addr, IPv6_ADDR_LEN);
                        encountered_failure = capture_passive_peer(&updated_passive_peers, nw_addr, r, host_buff, port_buff, &do_free_addr_info);
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
        batab_entry_t *e;
        batab_foreach_do((&ctx->passive_peers), e) {
            passive_peer_t *old = (passive_peer_t*) e->value;
            passive_peer_t *corresponding_new = batab_get(&updated_passive_peers, &old->addr);
            if (corresponding_new == NULL) {
                disconnect_and_discard_passive_peer(old);
            }
        }
        batab_foreach_do((&updated_passive_peers), e) {
            passive_peer_t *new = (passive_peer_t*) e->value;
            passive_peer_t *corresponding_old = batab_get(&ctx->passive_peers, &new->addr);
            if (corresponding_old == NULL) {
                connect_and_add_passive_peer(new);
            }
        }
    }

    batab_destory(&updated_passive_peers);

    fclose(f);
}

static int init_conn_sock(io_sock_t *sock, uint8_t *peer_addr) {
    memcpy(sock->d.conn.peer, peer_addr, MAX_NW_ADDR_LEN);
    if (init_backlog_ring(&sock->d.conn.tx_bl, CONN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate tx-backlog ring for sock: %d"), sock->fd);
        return -1;
    }
    if (init_backlog_ring(&sock->d.conn.rx_bl, CONN_RING_SZ) != 0) {
        log_crit("io", L("couldn't allocate rx-backlog ring for sock: %d"), sock->fd);
        return -1;
    }
    return 0;
}

static int init_out_conn_sock(io_sock_t *sock, passive_peer_t *peer) {
    sock->d.conn.outbound = 1;
    int ret = init_conn_sock(sock, peer->addr);
    sock->d.conn.outbound = 1;
    peer->addr_info = NULL;
}

void connect_and_add_passive_peer(io_ctx_t *ctx, passive_peer_t *peer) {
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
    int fd = setup_outbount_connection(peer);
    if (fd >= 0 && add_sock(ctx, fd, conn, init_out_conn_sock, peer) != 0) {
        log_warn("io", L("Failed to add passive-peer %s socket to io-ctx"), peer_copy->humanified_address);
        fd = -1;
    }
    if (fd < 0) {
        log_warn("io", L("Failed to setup connection to peer: %s, adding disconnected"), peer_copy->humanified_address);
        LIST_INSERT_HEAD(&ctx->disconnected_passive_peers, peer_copy, link);
        peer->addr_info = NULL; /* so it doesn't get free'd */
    }
}

void disconnect_and_discard_passive_peer(io_ctx_t *ctx, passive_peer_t *peer) {
    io_sock_t *sock = batab_get(&ctx->live_sockets, peer->addr);
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
    sockaddr remote_addr;
    socklen_t remote_addr_len;
    NET_ADDR(nw_addr);
    int conn_fd = accept(listener_sock, &remote_addr, &remote_addr_len);
    if (conn_sock == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EMFILE) return 0;
        log_warn("io", L("failed to accept socket"));
    }
    memset(nw_addr, 0, MAX_NW_ADDR_LEN);
    switch (remote_addr.sa_family) {
    case AF_INET:
        void *client_addr = (void *)&((struct sockaddr_in *) r->ai_addr)->sin_addr;
        memcpy(nw_addr, client_addr, IPv4_ADDR_LEN);
        break;
    case AF_INET6:
        void *client_addr = (void *)&((struct sockaddr_in6 *) r->sin6_addr)->s6_addr;
        memcpy(nw_addr, client_addr, IPv6_ADDR_LEN);
        break;
    default:
        log_warn("io", L("Encountered unexpected address-family: %d in inbound socket"), remote_addr.ai_family);
    }
    
    if (add_sock(sock->ctx, conn_fd, conn, init_conn_sock, client_addr) != 0) {
        log_warn("io", L("Couldn't plug inbound socket into io-ctx"));
    }
    return 1;
}

static inline void tun_io(io_sock_t *tun) {
    
}

static inline size_t backlog(ring_buff_t *r) {
    
    if (fw_bl > 0) return fw_bl;
    else return (r->sz - r->start) + r->end;
}

#define CONN_IO_OK 0
#define CONN_IO_OK_FULL 1
#define CONN_KILL -1

static inline int send_bl_batch(int fd, void *buff, size_t len, size_t *start) {
    size_t sent = send(fd, buff, len, MSG_NOSIGNAL);
    int full = 0;
    if (sent < 0) {
        full = (errno == EAGAIN || errno == EWOULDBLOCK);
        if (! full) {
            if (errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE) {
                return CONN_KILL;
            }
        }
        return CONN_IO_OK_FULL;
    } else {
        start += size;
        return CONN_IO_OK;
    }
}

static inline int send_bl(int fd, ring_buff_t *r) {
    if (r->sz == r->start) r->start = 0;
    size_t fw_bl = (r->end - r->start);
    if (fw_bl == 0) return;

    if (fw_bl > 0) {
        int ret = send_bl_batch(fd, r->buff + r->start, fw_bl, &r->start);
        r->drained = ((ret == CONN_IO_OK) && ((r->end - r->start) == 0));
        return ret;
    } else {
        fw_bl = (r->sz - r->start);
        int ret = send_bl_batch(fd, r->buff + r->start, fw_bl, &r->start);
        if ((ret == CONN_IO_OK) && ((r->sz - r->start) == 0)) {
            r->start = 0;
            r->drained = 0;
            return send_bl(fd, r);
        } else if (ret == CONN_IO_OK_FULL) {
            r->drained = 0;
        }
        return ret;
    }
    
}

static inline void conn_io(uint32_t event, io_sock_t *conn) {
    if ((event | EPOLLOUT) || conn->d.conn.tx.drained) {
        if (send_bl(conn->fd, &conn->d.conn.tx) == CONN_KILL) {
            destroy_sock(conn);
        }
    }
}

static inline void handle_io_evt(uint32_t event, io_sock_t *sock) {
    if (sock->typ == tun) {
        tun_io(sock);
    } else if (sock->typ == conn) {
        conn_io(event, sock);
    } else {
        assert(sock->typ == lstn);
        while(do_accept(sock));
    }
}

#define MAX_POLLED_EVENTS 256

int io(int tun_fd, const char* peer_file_path, const char *self_addr_v4, const char *self_addr_v6, int listener_port) {
    io_ctx_t *ctx;
    if ((ctx = init_io_ctx(tun_fd, self_addr_v4, self_addr_v6)) != NULL) {
        if (setup_listener(ctx, listener_port) == 0) {
            trigger_peer_reset();
            int num_evts;
            struct epoll_event evts[MAX_POLLED_EVENTS];
            while ( ! do_stop) {
                num_evts = epoll_wait(epollfd, evts, MAX_POLLED_EVENTS, -1);
                if (num_evts < 0) {
                    log_warn("io", L("io-poll failed"));
                } else {
                    for (int i = 0; i < num_evts; i++) {
                        handle_io_evt(evts[i].events, (io_sock_t *) evts[i].data.ptr);
                    }
                }
            }
            //reset_peers(ctx, peer_file_path, self_addr, listener_port);

            
            //poll loop

        }
    }
}
