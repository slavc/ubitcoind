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

int g_epoll_fd;
uint64_t g_conn_count;
uint64_t g_max_conn;
void *g_known_ip_addr_tree;
struct connect_queue_list g_connect_queue = STAILQ_HEAD_INITIALIZER(g_connect_queue);
struct connection_list g_connections = TAILQ_HEAD_INITIALIZER(g_connections);
uint64_t g_my_nonce;

bool is_ipv4_mapped(const void *a)
{
	return memcmp(a, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 10) == 0
	    && memcmp((const uint8_t *)a + 10, "\xff\xff", 2) == 0;
}

int ip_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct in6_addr));
}

bool is_known_peer(struct in6_addr *ip)
{
	struct in6_addr *ip_copy = malloc(sizeof(*ip));
	memcpy(ip_copy, ip, sizeof(*ip));

	struct in6_addr **node = tsearch(ip_copy, &g_known_ip_addr_tree, ip_cmp);
	if (*node == ip_copy) {
		return false;
	} else {
		// we already have this IP in the tree
		free(ip_copy);
		return true;
	}
}

struct peer *new_peer(int family, const void *sa)
{
	struct peer *peer;

	peer = calloc(1, sizeof(*peer));
	if (family == AF_INET) {
		memset(&peer->addr, 0, 10);
		memset((uint8_t *)&peer->addr + 10, 0xff, 2);
		memcpy((uint8_t *)&peer->addr + 12, &((struct sockaddr_in *)sa)->sin_addr, sizeof(peer->addr));
	} else {
		memcpy(&peer->addr, &((struct sockaddr_in6 *)sa)->sin6_addr, sizeof(peer->addr));
	}
	peer->conn = -1;
	peer->is_dead = true; // considered dead until we successfully connect to it
	return peer;
}

const char *str_peer(struct peer *peer)
{
	static char str_addr[INET6_ADDRSTRLEN] = "";
	if (inet_ntop(AF_INET6, &peer->addr, str_addr, sizeof(str_addr)) == NULL) {
		log_warning("inet_ntop: errno %d", errno);
	}
	return str_addr;
}

bool print_peer(FILE *f, struct peer *peer)
{
	if (f == NULL) {
		f = stdout;
	}
	fprintf(f, "%s,%u,%u,%lu,\"",
	    str_peer(peer), (unsigned)!peer->is_dead,
	    peer->version.protocol, peer->version.services);
	for (const char *s = peer->version.user_agent; *s != '\0'; s++) {
		if (*s == '"') {
			fputc('\\', f);
		}
		fputc(*s, f);
	}
	fprintf(f, "\",%u\n", peer->version.start_height);
	return true;
}

bool connect_to(struct peer *peer)
{
	int s;
	int family;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	socklen_t sa_len;

	if (is_ipv4_mapped(&peer->addr)) {
		family = AF_INET;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(MAINNET_PORT);
		memcpy(&sin.sin_addr, (uint8_t *)&peer->addr + 12, 4);
		sa = (void *)&sin;
		sa_len = sizeof(sin);
	} else {
		family = AF_INET6;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(MAINNET_PORT);
		memcpy(&sin6.sin6_addr, &peer->addr, 16);
		sa = (void *)&sin6;
		sa_len = sizeof(sin6);
	}

	s = socket(family, SOCK_STREAM, 0);
	if (s == -1) {
		int errno_copy = errno;
		log_warning("%s: socket: errno %d", str_peer(peer), errno_copy);
		return false;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) != 0) {
		int errno_copy = errno;
		log_warning("%s: fcntl O_NONBLOCK: errno %d", str_peer(peer), errno_copy);
		close(s);
		return false;
	}

	if (connect(s, sa, sa_len) != 0 && errno != EINPROGRESS) {
		int errno_copy = errno;
		log_warning("%s: connect: errno %d", str_peer(peer), errno_copy);
		close(s);
		return false;
	}
	peer->conn = s;
	peer->state = CONNECTING;
	return true;
}

void add_to_poll(struct peer *peer)
{
	struct epoll_event ev;

	peer->epevents = ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	ev.data.ptr = peer;
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		log_error("epoll_ctl add: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
}

void query_more_peers(void)
{
	struct peer *peer;
	while (g_conn_count < g_max_conn && !STAILQ_EMPTY(&g_connect_queue)) {
		peer = STAILQ_FIRST(&g_connect_queue);
		STAILQ_REMOVE_HEAD(&g_connect_queue, connect_queue_entry);
		if (!connect_to(peer)) {
			log_debug("%s: failed to connect to peer, marking as dead", str_peer(peer));
			peer->is_dead = true;
			print_peer(stdout, peer);
			free(peer);
		} else {
			log_debug("trying to connect to %s...", str_peer(peer));
			g_conn_count++;
			add_to_poll(peer);
		}
	}
}

void poll_out(struct peer *peer, bool enable)
{
	struct epoll_event ev;

	if (enable == true) {
		ev.events = peer->epevents | EPOLLOUT;
	} else {
		ev.events = peer->epevents & ~EPOLLOUT;
	}
	ev.data.ptr = peer;
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		log_error("%s: epoll_ctl: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
}

void poll_in(struct peer *peer, bool enable)
{
	struct epoll_event ev;

	if (enable == true) {
		ev.events = peer->epevents | EPOLLIN;
	} else {
		ev.events = peer->epevents & ~EPOLLIN;
	}
	ev.data.ptr = peer;
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		log_error("%s: epoll_ctl: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
}

bool send_msg(struct peer *peer)
{
	if (peer->out.buf == NULL || peer->out.len == 0) {
		return false;
	}

	if (peer->out.n == peer->out.len) {
		return true;
	}

	void *ptr = peer->out.buf + peer->out.n;
	size_t rem = peer->out.len - peer->out.n;
	ssize_t n = write(peer->conn, ptr, rem);

	if (n < 0) {
		if (errno != EAGAIN) {
			int errno_copy = errno;
			log_warning("%s: send_msg write: errno %d", str_peer(peer), errno_copy);
		}
		return false;
	} else if ((size_t)n == rem) {
		poll_out(peer, false);
		return true;
	} else {
		peer->out.n += n;
		return false;
	}
}

bool recv_msg(struct peer *peer, ssize_t *out_n)
{
	if (peer->in.buf == NULL) {
		return false;
	}

	if (peer->in.n < HDR_SIZE) {
		void *ptr = peer->in.buf + peer->in.n;
		size_t rem = HDR_SIZE - peer->in.n;
		ssize_t n = read(peer->conn, ptr, rem);
		*out_n = n;
		if (n < 0) {
			if (errno != EAGAIN) {
				int errno_copy = errno;
				log_warning("%s: recv_msg read: errno %d", str_peer(peer), errno_copy);
			}
			return false;
		} else if ((size_t)n < rem) {
			peer->in.n += n;
			return false;
		} else {
			// finished reading header
			peer->in.n += n;
			struct hdr hdr;
			if (!peek_hdr(peer->in.buf, peer->in.n, &hdr)) {
				log_warning("%s: received invalid message header", str_peer(peer));
				return false;
			}
			peer->in.len = HDR_SIZE + hdr.payload_size;
			if (peer->in.len > MAX_MSG_SIZE) {
				log_debug("%s: payload size exceeds maximum, disconnecting...", str_peer(peer));
				*out_n = 0;
				return false;
			}
			if (peer->in.len > peer->in.size) {
				peer->in.size = peer->in.len;
				// FIXME Check for NULL when calling *alloc
				peer->in.buf = realloc(peer->in.buf, peer->in.size);
			}
		}
	}

	void *ptr = peer->in.buf + peer->in.n;
	size_t rem = peer->in.len - peer->in.n;
	ssize_t n = read(peer->conn, ptr, rem);
	*out_n = n;
	if (n < 0) {
		if (errno != EAGAIN) {
			int errno_copy = errno;
			log_warning("%s: recv_msg read: errno %d", str_peer(peer), errno_copy);
		}
		return false;
	} else {
		peer->in.n += n;
		if (peer->in.n == peer->in.len) {
			peer->in.n = 0;
			return true;
		} else {
			return false;
		}
	}
}

void disconnect_from(struct peer *peer)
{
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, peer->conn, NULL) == -1) {
		int errno_copy = errno;
		log_error("%s: epoll_ctl del: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
	(void)close(peer->conn);
	peer->conn = -1;
	peer->state = DISCONNECTED;
}

void start_send_version_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_version_msg(peer->out.buf, peer->out.size, g_my_nonce);
	peer->state = SENDING_VERSION;
}


void start_send_verack_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_verack_msg(peer->out.buf, peer->out.size);
	peer->state = SENDING_VERACK;
	poll_out(peer, true);
}

void start_send_getaddr_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_getaddr_msg(peer->out.buf, peer->out.size);
	peer->state = SENDING_GETADDR;
	poll_out(peer, true);
}

bool is_peer_on_conn_list(struct peer *peer)
{

	return peer->connections_list_entry.tqe_prev != NULL
	    || peer->connections_list_entry.tqe_next != NULL;
}

void finalize_peer(struct peer *peer)
{
	if (is_peer_on_conn_list(peer)) {
		TAILQ_REMOVE(&g_connections, peer, connections_list_entry);
	}
	disconnect_from(peer);
	g_conn_count--;
	print_peer(stdout, peer);
	free(peer->in.buf);
	free(peer->out.buf);
	free(peer);
}

bool handle_pollout(struct peer *peer)
{
	// we've connected to a peer or can continue sneding a message
	switch (peer->state) {
	case CONNECTING:
		log_debug("%s: connected to peer", str_peer(peer));

		peer->is_dead = false;

		peer->in.size = 1024;
		peer->in.buf = malloc(peer->in.size);
		peer->in.len = 0;
		peer->in.n = 0;

		peer->out.size = 512;
		peer->out.buf = malloc(peer->out.size);
		peer->out.len = 0;
		peer->out.n = 0;

		start_send_version_msg(peer);
		break;

	case SENDING_VERSION:
		if (send_msg(peer)) {
			peer->state = EXPECTING_VERSION;
		}
		break;

	case SENDING_VERACK:
		if (send_msg(peer)) {
			// finished sending verack message, now send getaddr
			start_send_getaddr_msg(peer);
		}
		break;

	case SENDING_GETADDR:
		if (send_msg(peer)) {
			peer->state = EXPECTING_ADDR;
		}
		break;

	default:
		break;
	}

	return true;
}

bool handle_pollin(struct peer *peer)
{
	// we've received a piece of message from one of the peers
	ssize_t n_recv = 0;
	bool have_complete_msg;

	have_complete_msg = recv_msg(peer, &n_recv);

	if (!have_complete_msg) {
		if (n_recv <= 0) {
			if (n_recv == 0) {
				log_debug("%s: peer closed connection...", str_peer(peer));
			} else {
				log_debug("%s: read error", str_peer(peer));
			}
			finalize_peer(peer);
			return false;
		}
		return true;
	}

	struct hdr hdr;
	if (!unpack_hdr(peer->in.buf, peer->in.len, &hdr)) {
		log_debug("%s: received message with invalid header, disconnecting...", str_peer(peer));
		finalize_peer(peer);
		return false;
	}

	if (peer->state == EXPECTING_VERSION) {
		if (unpack_version_msg(peer->in.buf, peer->in.len, &peer->version)) {
			start_send_verack_msg(peer);
		} else {
			log_debug("%s: received invalid version message, disconnecting...", str_peer(peer));
			finalize_peer(peer);
			return false;
		}
	} else if (peer->state == EXPECTING_ADDR) {
		if (!is_addr_msg(&hdr)) {
			log_debug("%s: got %.12s message instead of addr", str_peer(peer), hdr.cmd);
			return true;
		}

		struct addr addr;
		if (!unpack_addr_msg(peer->in.buf, peer->in.len, &addr)) {
			log_warning("%s: got bad addr msg", str_peer(peer));
			return false;
		}

		struct addr_record rec;
		while (unpack_addr_record(&addr, &rec)) {
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
			void *addr_ptr;
			int addr_family;
			if (is_ipv4_mapped(&rec.ip)) {
				addr_family = AF_INET;
				sin.sin_family = AF_INET;
				addr_ptr = &sin;
				// FIXME Change new_peer() interface so we don't have to do this.
				memcpy(&sin.sin_addr, (uint8_t *)&rec.ip + 12, 4);
			} else if (g_cfg.ipv6.disable) {
				continue;
			} else {
				addr_family = AF_INET6;
				sin6.sin6_family = AF_INET6;
				addr_ptr = &sin6;
				memcpy(&sin6.sin6_addr, &rec.ip, 16);
			}
			if (!is_known_peer(&rec.ip)) {
				struct peer *peer_rec = new_peer(addr_family, addr_ptr);
				fprintf(stdout, "%s,", str_peer(peer_rec));
				fprintf(stdout, "%s\n", str_peer(peer));
				log_debug("%s: adding new peer:", str_peer(peer));
				log_debug("    %s", str_peer(peer_rec));
				STAILQ_INSERT_TAIL(&g_connect_queue, peer_rec, connect_queue_entry);
			}
		}

		log_debug("%s: done getting peers, disconnecting...", str_peer(peer));
		finalize_peer(peer);
	}
	return false;
}

bool is_timed_out(struct peer *peer)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		int errno_copy = errno;
		log_error("%s: clock_gettime: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
	return t.tv_sec >= peer->timeout.tv_sec;
}
