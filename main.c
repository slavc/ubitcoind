/*
 * Copyright (c) 2018 Sviatoslav Chagaev <sviatoslav.chagaev@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>
#include <search.h>

#include "cfg.h"
#include "protocol.h"
#include "pack.h"
#include "p2p.h"
#include "log.h"

#define MAX_WAIT 90 // seconds; max peer inactivity before disconnecting from it
#define MAX_EPOLL_EVENTS 2000 // max number of events epoll will report
#define MAX_CONN_LIMIT 60000 // max concurrent connections if nofiles ulimit is not set

bool g_quit = false;

const char *seeds[] = {
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
};

struct timespec get_time(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		log_error("clock_gettime: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	return t;
}

void update_timeout(struct peer *peer)
{
	peer->timeout = get_time();
	peer->timeout.tv_nsec = 0;
	peer->timeout.tv_sec += MAX_WAIT;
}

int get_epoll_timeout(struct peer *peer)
{
	struct timespec t = get_time();
	t.tv_nsec = 0;
	if (peer->timeout.tv_sec < t.tv_sec) {
		return 0;
	}
	return (int)(peer->timeout.tv_sec - t.tv_sec)*1000;
}

void set_max_conn(void)
{
	struct rlimit rlim;
	int open_count;
	long rc;

	for (open_count = 0; fcntl(open_count, F_GETFD, NULL) != -1; open_count++) {
		/* empty */
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		if (rlim.rlim_cur == RLIM_INFINITY) {
			g_max_conn = MAX_CONN_LIMIT;
		} else {
			g_max_conn = rlim.rlim_cur - open_count;
		}
	} else if ((rc = sysconf(_SC_OPEN_MAX)) > 0) {
		g_max_conn = rc - open_count;
	} else {
		g_max_conn = _POSIX_OPEN_MAX - open_count;
	}
}

bool handle_epoll_event(struct epoll_event *ev)
{
	struct peer *peer;
	int rc;
	int optval;
	socklen_t optlen;

	peer = ev->data.ptr;

	optlen = sizeof(optval);
	rc = getsockopt(peer->conn, SOL_SOCKET, SO_ERROR, &optval, &optlen); 
	if (rc == -1 || optval != 0) {
		log_debug("%s: connection failed, rc=%d, SO_ERROR=%d...", str_peer(peer), rc, optval);
		finalize_peer(peer);
		return false;
	}

	if (ev->events & EPOLLOUT) {
		log_debug("%s: EPOLLOUT event", str_peer(peer));
		return handle_pollout(peer);
	} else if (ev->events & EPOLLIN) {
		log_debug("%s: EPOLLIN event", str_peer(peer));
		return handle_pollin(peer);
	} else /*if (ev->events & (EPOLLERR | EPOLLRDHUP))*/ {
		log_debug("%s: EPOLLERR or EPOLLRDHUP event, disconnecting...", str_peer(peer));
		peer->is_dead = true;
		finalize_peer(peer);
		return false;
	}
}

void mainloop(void)
{
	struct epoll_event events[MAX_EPOLL_EVENTS];
	int num_events;
	int timeout;
	struct peer *peer;

	while (!g_quit && (g_conn_count > 0 || !STAILQ_EMPTY(&g_connect_queue))) {
		log_debug("%lu connections", (long unsigned)g_conn_count);

		query_more_peers();

		if (!TAILQ_EMPTY(&g_connections)) {
			peer = TAILQ_FIRST(&g_connections);
			timeout = get_epoll_timeout(peer);
			log_debug("using epoll timeout %d ms from peer %s", timeout, str_peer(peer));
		} else {
			timeout = -1;
		}

		num_events = epoll_wait(g_epoll_fd, events, MAX_EPOLL_EVENTS, timeout);
		if (num_events < 0) {
			if (errno == EINTR) {
				log_debug("interrupted");
				break;
			}
			log_warning("epoll_wait: errno %d", errno);
			continue;
		}
		if (num_events == 0) {
			while (!TAILQ_EMPTY(&g_connections)) {
				peer = TAILQ_FIRST(&g_connections);
				if (is_timed_out(peer)) {
					log_debug("%s: timed out, disconnecting...", str_peer(peer));
					finalize_peer(peer);
				} else {
					break;
				}
			}
			continue;
		}
		log_debug("processing %d events", num_events);
		for (int i = 0; i < num_events; i++) {
			if (handle_epoll_event(&events[i])) {
				// all ok, we'll be continuing talking to this peer,
				// so update it's timeout and reinsert it at the tail of the timeout list
				peer = events[i].data.ptr;
				update_timeout(peer);
				if (is_peer_on_conn_list(peer)) {
					// this peer is already on the list, need to remove first
					TAILQ_REMOVE(&g_connections, peer, connections_list_entry);
				}
				TAILQ_INSERT_TAIL(&g_connections, peer, connections_list_entry);
			}
		}
	}
}

void get_initial_peers(void)
{
	for (size_t i = 0; i < NELEMS(seeds); i++) {
		struct addrinfo *result;
		struct addrinfo *ai;

		int error = getaddrinfo(seeds[i], NULL, NULL, &result);
		if (error) {
			log_warning("getaddrinfo %s failed: errno %d", seeds[i], errno);
			continue;
		}

		log_debug("adding peers from seed %s...", seeds[i]);
		for (ai = result; ai != NULL; ai = ai->ai_next) {
			if (ai->ai_protocol != IPPROTO_TCP) {
				continue;
			}
			if (ai->ai_socktype != SOCK_STREAM) {
				continue;
			}
			struct in6_addr addr;
			if (ai->ai_family == AF_INET) {
				struct sockaddr_in *sin = (void *)ai->ai_addr;
				// make an IPv4-mapped IPv6-address
				memset(&addr, 0, 10);
				memset((uint8_t *)&addr + 10, 0xff, 2);
				memcpy((uint8_t *)&addr + 12, &sin->sin_addr, 4);
			} else if (ai->ai_family == AF_INET6) {
				if (g_cfg.ipv6.disable) {
					continue;
				}
				struct sockaddr_in6 *sin6 = (void *)ai->ai_addr;
				memcpy(&addr, &sin6->sin6_addr, sizeof(addr));
			} else {
				continue;
			}
			if (!is_known_peer(&addr)) {
				struct peer *peer = new_peer(ai->ai_family, ai->ai_addr);
				fprintf(stdout, "%s,%s\n", str_peer(peer), seeds[i]);
				STAILQ_INSERT_TAIL(&g_connect_queue, peer, connect_queue_entry);
			}
		}

		freeaddrinfo(result);
	}
}

void init_program(void)
{
	g_log_stream = stdout;

	srand(time(NULL));
	g_my_nonce = ((uint64_t)rand() << 32) | (uint64_t)rand();

	g_epoll_fd = epoll_create(1);
	if (g_epoll_fd == -1) {
		log_error("epoll_create: errno %d", errno);
		exit(EXIT_FAILURE);
	}
}

void print_usage(void)
{
	printf(
	    "usage: mapbtc [--noipv6] [--verbose]\n"
	    "  --noipv6   ignore IPv6 peers\n"
	    "  --verbose  print debug output\n");
}

void parse_args(int argc, char **argv)
{
	while (++argv, --argc) {
		if (strcmp(*argv, "-h") == 0 || strcmp(*argv, "--help") == 0) {
			print_usage();
			exit(EXIT_SUCCESS);
		} else if (strcmp(*argv, "--noipv6") == 0) {
			g_cfg.ipv6.disable = true;
		} else if (strcmp(*argv, "--verbose") == 0) {
			g_cfg.ubitcoind.verbose = true;
		} else {
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	init_program();
	merge_cfg("/etc/ubitcoind.cfg");
	merge_cfg("./ubitcoind.cfg");
	parse_args(argc, argv);
	get_initial_peers();
	set_max_conn();
	mainloop();

	return 0;
}
