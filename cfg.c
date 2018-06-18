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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "cfg.h"
#include "log.h"

struct cfg g_cfg = {
	.ubitcoind.verbose = 0,
	.peers.target = 100,
	.ipv6.disable = 0,
};

void merge_cfg(const char *path)
{
	FILE *f;

	f = fopen(path, "r");
	if (f == NULL) {
		return;
	}

	char key[128];
	int val;
	int n;
	while ((n = fscanf(f, "%127s = %d", key, &val)) != EOF) {
		if (n != 2)
			continue;
		if (!strcmp(key, "ubitcoind.verbose")) {
			g_cfg.ubitcoind.verbose = val;
		} else if (!strcmp(key, "peers.target")) {
			g_cfg.peers.target = val;
		} else if (!strcmp(key, "ipv6.disable")) {
			g_cfg.ipv6.disable = val;
		} else {
			log_warning("%s: unrecognized configuration option '%s'", path, key);
		}
	}

	(void)fclose(f);
}
