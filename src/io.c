#include <stdio.h>

#include "io.h"
#include "common.h"

#define LISTEN_BACKLOG 1024

typedef struct io_ctx_s io_ctx_t;
typedef struct io_sock_s io_sock_t;

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
            char peer_host;
            int peer_port;
        } conn;
    } d;
};

struct io_ctx_s {
    LIST_HEAD(sock_s, io_sock_s) live_sockets;
    LIST_HEAD(sock_s, io_sock_s) dead_sockets;
    int tun_fd;
    int epoll_fd;
};

static io_ctx_t * init_io_ctx(int tun_fd) {
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
    LIST_INIT(ctx->live_sockets);
    LIST_INIT(ctx->dead_sockets);
    
    return ctx;
}

static inline void destroy_sock(io_sock_t *sock) {
    if (NULL == sock) return;
    log_debug("io", L("destroying socket of type: %d (fd: %d)"), sock->typ, sock->fd);

    switch(sock->typ) {
    case conn:
        teardown_route(sock);
        free(sock->d.conn.peer_host);
        break;
    case lstn:
    case tun:
    default:
    }
    if (epoll_ctl(sock->ctx, EPOLL_CTL_DEL, sock->fd, NULL)) {
        log_warn("io", L("removal from epoll context for fd: %d failed"), sock->fd);
    }
    LIST_REMOVE((sock->alive ? &ctx->live_sockets : &ctx->dead_sockets), sock, io_sock_s, link);
    close(sock->fd);
    free(sock);
}

static inline int add_sock(io_ctx_t *ctx, int fd, int typ, int alive, io_sock_t **res) {
    log_debug("io", L("creating socket of type: %d (fd: %d)"), typ, fd);
    if (res != NULL) *res = NULL;
    io_sock_t *sock = calloc(1, sizeof(io_sock_t));
    if (sock == NULL) {
        log_warn("io", L("failed to allocate memory for listerner socket object, closing fd"));
        close(fd);
        return NULL;
    }
    sock->fd = fd;
    sock->ctx = ctx;

    LIST_INSERT_HEAD((alive ? &ctx->live_sockets : &ctx->dead_sockets), sock, link);
    sock->evt.events = EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLET;
    sock->evt.data.ptr = sock;
    
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sock->fd, sock->evt) != 0) {
        log_warn("io", L("failed to add fd to polling context"));
        destroy_sock(sock);
        return -1;
    }

    if (res != NULL) *res = sock;
    return 0;
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


        if (add_sock(ctx, sock, lstn, 1, NULL) != 0) {
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

static int reset_peers(io_ctx_t *ctx, const char* peer_file_path, const char* self_addr, int expected_port) {
    char peer[MAX_ADDR_LEN];
    char host_buff[MAX_ADDR_LEN];
    char port_buff[8];
    
    FILE *f = fopen(peer_file_path, "r");

    struct addrinfo hints, *res, *r;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_buff, sizeof(port_buff), "%d", expected_port);
    
    while (fgets(peer, MAX_HOST_LEN, f) != NULL) {
        res = NULL
        if (getaddrinfo(peer, port_buff, &hints, &res) != 0) {
            log_warn("io", L("ignoring peer: %s"), peer);
            continue;
        }

        for (int i = 0; r != NULL; r = r->ai_next, i++) {
            if (getnameinfo(r->ai_addr, r->ai_addrlen,
                            host_buf, sizeof(host_buf),
                            port_buf, sizeof(port_buf),
                            NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
                log_warn("io", L("failed to get name-info for peer: %s"), peer);
            }
            int become_client = strcmp(self_addr, peer) < 0;
            log_info("io", L("identified peer %s => %s [port: %s] (im client: %d)"), peer, host_buff, port_buff, become_client);

            if (become_client) {
                int c_fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
                if (c_fd < 0) {
                    log_warn("io", L("could not create socket for connecting to peer: %s"), peer);
                } else {
                    int connected = (connect(c_fd, res->ai_addr, res->ai_addrlen) == 0);
                    if (! connected) {
                        log_warn("io", L("could not connect to peer: %s, will retry later"), peer);
                    } else {
                        log_info("io", L("connnected as client to peer: %s"), peer);
                    }
                    io_sock_t *sock;
                    if (add_sock(ctx, c_fd, conn, connected, &sock) == 0) {
                        sock->d.conn.peer_host = strdup(host_buff);
                        sock->d.conn.peer_port = atoi(port_buff);
                    } else {
                        
                    }

                    
                }
            }
        }
    }
    

    fread(data, fsize, 1, f);
    data[fsize] = 0;

    fclose(f);
}

int io(int tun_fd, const char* peer_file_path, int listener_port) {
    io_ctx_t *ctx;
    if ((ctx = init_io_ctx(tun_fd)) != NULL) {
        if (setup_listener(ctx, listener_port) == 0) {
            reset_peers(ctx, peer_file_path, self_addr, listener_port);

            
            //poll loop

        }
    }
}
