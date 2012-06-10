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

#ifndef ISC_BLOOMRATE_H
#define ISC_BLOOMRATE_H 1

/*! \file isc/bloomrate.h
 * \brief
 * Measure per-client query rates using a Bloom filter
 */

#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

isc_result_t
isc_bloomrate_create(isc_uint32_t size, isc_uint32_t hashes,
		     isc_mem_t *mctx, isc_timermgr_t *timermgr,
		     isc_task_t *task, isc_bloomrate_t **brp);
/*%<
 * Create a new client rate measurement Bloom filter.
 *
 * The bloomrate object requires periodic cleaning, performed by a
 * timer managed by the given timermgr within the given task.
 */

void
isc_bloomrate_attach(isc_bloomrate_t *source, isc_bloomrate_t **target);
/*%<
 * Attach to a client rate measurer.
 */

void
isc_bloomrate_detach(isc_bloomrate_t **brp);
/*%<
 * Detach from a client rate measurer.
 */

isc_uint32_t
isc_bloomrate_add(isc_bloomrate_t *br, isc_sockaddr_t *sa, isc_uint32_t inc);
/*%<
 * Record an event for the given client, and return its current rate.
 * The increment is the size of the event, e.g. packet size.
 */

#define isc_bloomrate_bump(br, sa) isc_bloomrate_add(br, sa, 1)

ISC_LANG_ENDDECLS

#endif /* ISC_BLOOMRATE_H */
