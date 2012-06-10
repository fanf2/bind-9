/*
 * Copyright (C) 2012 Tony Finch <dot@dotat.at> <fanf2@cam.ac.uk>
 * Copyright (C) 2012 The University of Cambridge
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: ratelimiter_test.c,v 1.18 2007/06/19 23:46:59 tbox Exp $ */

#include <config.h>

#include <isc/app.h>
#include <isc/bloomrate.h>
#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/sockaddr.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#define	HASHLEN 255

isc_bloomrate_t *br = NULL;
isc_taskmgr_t *taskmgr = NULL;
isc_timermgr_t *timermgr = NULL;
isc_task_t *g_task = NULL;
isc_mem_t *mctx = NULL;
isc_entropy_t *ectx = NULL;
isc_timer_t *ticker = NULL;
isc_timer_t *closer = NULL;

struct in_addr g_in;

static void
bump(struct in_addr *in) {
	isc_sockaddr_t sa;
	isc_buffer_t buf;
	char msg[16];
	isc_uint32_t r;

	isc_sockaddr_fromin(&sa, in, 0);
	r = isc_bloomrate_bump(br, &sa);

	isc_buffer_init(&buf, msg, sizeof(msg));
	isc_sockaddr_totext(&sa, &buf);
	printf("%6d  %.*s\n", r,
	       (int)isc_buffer_usedlength(&buf),
	       (char*)isc_buffer_base(&buf));
	isc_buffer_invalidate(&buf);
}

static void
do_tick(isc_task_t *task, isc_event_t *event) {
	struct in_addr in;

	UNUSED(task);
	isc_event_free(&event);

	isc_random_get(&in.s_addr);
	in.s_addr &= 0x00F00000;

	bump(&in);
	bump(&g_in);
}

static void
do_close(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	UNUSED(event);
	printf("shutdown\n");
	isc_timer_detach(&ticker);
	isc_timer_detach(&closer);
	isc_app_shutdown();
}

int
main(int argc, char *argv[]) {
	isc_interval_t tick_interval;
	isc_interval_t close_interval;

	UNUSED(argc);
	UNUSED(argv);

	isc_app_start();

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_entropy_create(mctx, &ectx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_hash_create(mctx, ectx, HASHLEN) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 3, 0, &taskmgr) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_create(taskmgr, 0, &g_task) ==
		      ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_bloomrate_create(1023, 4,
					   mctx, timermgr, g_task,
					   &br) == ISC_R_SUCCESS);

	isc_interval_set(&tick_interval, 0, 10*1000*1000);
	RUNTIME_CHECK(isc_timer_create(timermgr, isc_timertype_ticker,
				       NULL, &tick_interval,
				       g_task, do_tick, NULL,
				       &ticker) == ISC_R_SUCCESS);

	isc_interval_set(&close_interval, 1, 0);
	RUNTIME_CHECK(isc_timer_create(timermgr, isc_timertype_once,
				       NULL, &close_interval,
				       g_task, do_close, NULL,
				       &closer) == ISC_R_SUCCESS);

	isc_random_get(&g_in.s_addr);

	isc_app_run();

	isc_bloomrate_detach(&br);

	isc_task_destroy(&g_task);
	isc_timermgr_destroy(&timermgr);
	isc_taskmgr_destroy(&taskmgr);

	isc_mem_stats(mctx, stdout);

	isc_app_finish();
	return (0);
}
