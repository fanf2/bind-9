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

#include <string.h>

#include <isc/bloomrate.h>
#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/types.h>

/*%
 * We set a fixed interval for the periodic aging job.
 * This is fairly small so we catch rate spikes quickly.
 */
#define BR_INTERVAL 5

/*%
 * The attenuation factor determines how quickly we forget a client's
 * past behaviour. (Take care not to overflow!)
 */
#define BR_ATTENUATE(x) ((x)/2 + (x)/4)

/*%
 * The value stored in a hash bucket needs to be adjusted to get the
 * client's actual rate. See bloomrate.h.
 */
#define BR_RATE(x) (((x) - BR_ATTENUATE(x)) / BR_INTERVAL)

/*%
 * Periodic aging job.
 */
static void
bloomrate_tick(isc_task_t *task, isc_event_t *event) {
	isc_bloomrate_t *br;
	isc_uint32_t *t, i, m;

	UNUSED(task);

	br = (isc_bloomrate_t *)event->ev_arg;
	isc_event_free(&event);

	REQUIRE(ISC_BLOOMRATE_VALID(br));

	m = br->size;
	t = br->table;
	for (i = 0; i < m; i++)
		t[i] = BR_ATTENUATE(t[i]);
}

isc_uint32_t
isc_bloomrate_add(isc_bloomrate_t *br, isc_sockaddr_t *sa, isc_uint32_t inc) {
	isc_uint32_t *t, h1, h2, h, i, n, m, min;

	REQUIRE(ISC_BLOOMRATE_VALID(br));

	h1 = isc_sockaddr_hashnet(sa, ISC_FALSE);
	h2 = isc_sockaddr_hashnet(sa, ISC_TRUE);
	n = br->hashes;
	m = br->size;
	t = br->table;

	/* client's rate is the smallest bucket */
	min = ISC_UINT32_MAX;
	for (h = h1 % m, i = 0; i < n; i++, h = (h + h2) % m)
		if (t[h] < min)
			min = t[h];

	/* careful about overflow */
	if (min < ISC_UINT32_MAX - inc)
		min += inc;
	else
		min = ISC_UINT32_MAX;

	/* conservative update */
	for (h = h1 % m, i = 0; i < n; i++, h = (h + h2) % m)
		if (t[h] < min)
			t[h] = min;

	return (BR_RATE(min));
}

/*%
 * Memory calculations.
 */
#define BR_MEMSIZE(size) (sizeof(isc_uint32_t) * (size-1) + sizeof(isc_bloomrate_t))
#define BR_TABSIZE(size) (sizeof(isc_uint32_t) * (size))

isc_result_t
isc_bloomrate_create(isc_uint32_t size, isc_uint32_t hashes, isc_mem_t *mctx,
		     isc_timermgr_t *timermgr, isc_task_t *task,
		     isc_bloomrate_t **brp) {
	isc_bloomrate_t *br = NULL;
	isc_interval_t interval;
	isc_result_t result;

	br = isc_mem_get(mctx, BR_MEMSIZE(size));
	if (br == NULL)
		return (ISC_R_NOMEMORY);

	br->magic = ISC_BLOOMRATE_MAGIC;
	br->mctx = NULL;
	isc_mem_attach(mctx, &br->mctx);
	br->timer = NULL;
	br->hashes = hashes;
	br->size = size;
	memset(br->table, 0, BR_TABSIZE(size));

	isc_interval_set(&interval, BR_INTERVAL, 0);
	result = isc_timer_create(timermgr, isc_timertype_ticker,
				  NULL, &interval,
				  task, bloomrate_tick, (void *)br,
				  &br->timer);
	if (result != ISC_R_SUCCESS)
		goto free_mem;

	*brp = br;
	return (ISC_R_SUCCESS);

free_mem:
	isc_mem_put(mctx, br, BR_MEMSIZE(size));
	return (result);
}

void
isc_bloomrate_destroy(isc_bloomrate_t **brp) {
	isc_bloomrate_t *br = *brp;
	isc_mem_t *mctx;

	isc_timer_detach(&br->timer);
	mctx = br->mctx;
	isc_mem_put(mctx, br, BR_MEMSIZE(br->size));
	isc_mem_detach(&mctx);
	*brp = NULL;
}
