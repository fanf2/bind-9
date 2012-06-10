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
#include <isc/sockaddr.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/types.h>
#include <isc/util.h>

/*! \file isc/bloomrate.c
 * \brief
 * Measure per-client query rates using a Bloom filter
 *
 * We store clients' query rate measurements in a hash table which is
 * accessed like a Bloom filter, except that rather than being a
 * present/absent bit, each entry is a rate measurement. A number of
 * hashes are calculated for the current client, and the client's rate
 * is the minimum of the buckets indexed by the hashes. To record a
 * query, increment the rate value in all the minimum-valued hash
 * buckets.
 *
 * There is a periodic task to age old data out of the hash table.
 * Every p seconds all the buckets are multiplied by an attenuation
 * factor 0 <= a < 1. If a client is querying at a constant rate r the
 * measured value from the hash table r' comes from the sum of the
 * resulting geometric progression, which is p * r / (1 - a). So to
 * calculate the client's actual rate from the value in the hash
 * table, r = r' * (1 - a) / p.
 *
 * The reference for this code is "network applications of Bloom filters"
 * by Andrei Broder and Michael Mitzenmacher.
 * http://www.eecs.harvard.edu/~michaelm/postscripts/im2005b.pdf
 * The specific technique for measuring each client's rate is
 * described in section 8.1.
 *
 * Also worth noting is "less hashing, same performance"
 * by Adam Kirsch and Michael Mitzenmacher
 * http://www.eecs.harvard.edu/~kirsch/pubs/bbbf/esa06.pdf
 * which shows that Bloom filters work just as well with a linear
 * combination of two independent hashes as they do with multiple
 * independent hashes.
 */

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
 * Convert hash bucket value to rate as described above.
 */
#define BR_RATE(x) (((x) - BR_ATTENUATE(x)) / BR_INTERVAL)

#define ISC_BLOOMRATE_MAGIC	ISC_MAGIC('B', 'l', 'o', 'o')
#define ISC_BLOOMRATE_VALID(br)	ISC_MAGIC_VALID(br, ISC_BLOOMRATE_MAGIC)

struct isc_bloomrate {
	unsigned int		magic;
	int			refs;
	isc_mutex_t		lock;
	isc_mem_t *		mctx;
	isc_task_t *		task;
	isc_timer_t *		timer;
	isc_uint32_t		hashes;	/*%< Number of times to hash */
	isc_uint32_t		size;	/*%< Number of buckets in table */
	isc_uint32_t		table[1];
};

/*%
 * Periodic aging job.
 */
static void
bloomrate_tick(isc_task_t *task, isc_event_t *event) {
	isc_bloomrate_t *br;
	isc_uint32_t *t, i, m;

	br = (isc_bloomrate_t *)event->ev_arg;

	UNUSED(task);
	isc_event_free(&event);

	REQUIRE(ISC_BLOOMRATE_VALID(br));
	LOCK(&br->lock);

	m = br->size;
	t = br->table;
	for (i = 0; i < m; i++)
		t[i] = BR_ATTENUATE(t[i]);

	UNLOCK(&br->lock);
}

isc_uint32_t
isc_bloomrate_add(isc_bloomrate_t *br, isc_sockaddr_t *sa, isc_uint32_t inc) {
	isc_uint32_t *t, h1, h2, h, i, n, m, min;

	REQUIRE(ISC_BLOOMRATE_VALID(br));
	LOCK(&br->lock);

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

	UNLOCK(&br->lock);
	return (BR_RATE(min));
}

/*%
 * Memory calculations.
 */
#define BR_MEMSIZE(size) (sizeof(isc_bloomrate_t) + \
			  sizeof(isc_uint32_t) * (size-1))
#define BR_TABSIZE(size) (sizeof(isc_uint32_t) * (size))

isc_result_t
isc_bloomrate_create(isc_uint32_t size, isc_uint32_t hashes,
		     isc_mem_t *mctx, isc_timermgr_t *timermgr,
		     isc_taskmgr_t *taskmgr, isc_bloomrate_t **brp) {
	isc_bloomrate_t *br = NULL;
	isc_interval_t interval;
	isc_result_t result;

	INSIST(brp != NULL && *brp == NULL);

	br = isc_mem_get(mctx, BR_MEMSIZE(size));
	if (br == NULL)
		return (ISC_R_NOMEMORY);

	br->magic = ISC_BLOOMRATE_MAGIC;
	br->refs  = 1;
	br->mctx = NULL;
	isc_mem_attach(mctx, &br->mctx);
	br->task = NULL;
	br->timer = NULL;
	br->hashes = hashes;
	br->size = size;
	memset(br->table, 0, BR_TABSIZE(size));

	result = isc_mutex_init(&br->lock);
	if (result != ISC_R_SUCCESS)
		goto free_mem;

	result = isc_task_create(taskmgr, 0, &br->task);
	if (result != ISC_R_SUCCESS)
		goto free_mutex;

	isc_interval_set(&interval, BR_INTERVAL, 0);
	result = isc_timer_create(timermgr, isc_timertype_ticker,
				  NULL, &interval, br->task,
				  bloomrate_tick, (void *)br,
				  &br->timer);
	if (result != ISC_R_SUCCESS)
		goto free_task;

	*brp = br;
	return (ISC_R_SUCCESS);

free_task:
	isc_task_destroy(&br->task);
free_mutex:
	DESTROYLOCK(&br->lock);
free_mem:
	isc_mem_put(mctx, br, BR_MEMSIZE(size));
	isc_mem_detach(&mctx);
	return (result);
}

void
isc_bloomrate_attach(isc_bloomrate_t *source, isc_bloomrate_t **target) {
	REQUIRE(source != NULL);
	REQUIRE(target != NULL && *target == NULL);

	LOCK(&source->lock);
	REQUIRE(source->refs > 0);
	source->refs++;
	INSIST(source->refs > 0);
	UNLOCK(&source->lock);
	*target = source;
}

void
isc_bloomrate_detach(isc_bloomrate_t **brp) {
	isc_bloomrate_t *br = *brp;
	isc_boolean_t free_now = ISC_FALSE;
	isc_mem_t *mctx;

	LOCK(&br->lock);
	REQUIRE(br->refs > 0);
	br->refs--;
	if (br->refs == 0) {
		(void)isc_timer_reset(br->timer, isc_timertype_inactive,
				      NULL, NULL, ISC_FALSE);
		isc_timer_detach(&br->timer);
		isc_task_destroy(&br->task);
		free_now = ISC_TRUE;
	}
	UNLOCK(&br->lock);

	if (free_now) {
		DESTROYLOCK(&br->lock);
		mctx = br->mctx;
		isc_mem_put(mctx, br, BR_MEMSIZE(br->size));
		isc_mem_detach(&mctx);
	}

	*brp = NULL;
}
