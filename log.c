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
#include <stdarg.h>
#include <stdbool.h>

#include "cfg.h"
#include "log.h"

FILE *g_log_stream = NULL;

void log_debug(const char *fmt, ...)
{
	if (!g_cfg.ubitcoind.verbose) {
		return;
	}
	va_list ap;
	fprintf(g_log_stream, "debug: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

void log_warning(const char *fmt, ...)
{
	va_list ap;
	fprintf(g_log_stream, "warning: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

void log_error(const char *fmt, ...)
{
	va_list ap;
	fprintf(g_log_stream, "error: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

