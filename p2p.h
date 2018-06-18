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

#ifndef UBITCOIND_P2P_H
#define UBITCOIND_P2P_H

#include <sys/queue.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct peer {
	struct in6_addr addr;
	struct timespec timeout;
	STAILQ_ENTRY(peer) connect_queue_entry;
	TAILQ_ENTRY(peer) connections_list_entry;
	uint32_t epevents; // epoll event mask
	int conn; // tcp connection socket
	enum {
		DISCONNECTED,
		CONNECTING,
		SENDING_VERSION,
		EXPECTING_VERSION,
		SENDING_MESSAGE,
		EXPECTING_MESSAGE,
		SENDING_VERACK,
		SENDING_GETADDR,
		EXPECTING_ADDR,
	} state;
	struct peer_msg_buf {
		uint8_t *buf;
		size_t size; // size of buffer pointed to by buf
		size_t len; // length of message (to be sent or expected)
		size_t n; // number of bytes transmitted/received
	} in, out;
	struct version version;
	unsigned is_dead:1; // we couldn't connect to it
};
STAILQ_HEAD(connect_queue_list, peer) g_connect_queue;
TAILQ_HEAD(connection_list, peer) g_connections;

extern int g_epoll_fd;
extern uint64_t g_conn_count;
extern uint64_t g_max_conn;
extern void *g_known_ip_addr_tree;
extern uint64_t g_my_nonce;

struct peer *new_peer(int family, const void *sa);
const char *str_peer(struct peer *peer);
bool print_peer(FILE *f, struct peer *peer);
bool connect_to(struct peer *peer);
void add_to_poll(struct peer *peer);
void query_more_peers(void);
void poll_out(struct peer *peer, bool enable);
void poll_in(struct peer *peer, bool enable);
bool send_msg(struct peer *peer);
bool recv_msg(struct peer *peer, ssize_t *out_n);
void disconnect_from(struct peer *peer);
void start_send_version_msg(struct peer *peer);
void start_send_verack_msg(struct peer *peer);
void start_send_getaddr_msg(struct peer *peer);
bool is_peer_on_conn_list(struct peer *peer);
void finalize_peer(struct peer *peer);
bool handle_pollout(struct peer *peer);
bool handle_pollin(struct peer *peer);
bool is_timed_out(struct peer *peer);
bool is_known_peer(struct in6_addr *ip);
int ip_cmp(const void *a, const void *b);

#endif
