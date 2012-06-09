/*
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

#ifndef ISC_BLOOMLIMIT_H
#define ISC_BLOOMLIMIT_H 1

/*! \file isc/bloomlimit.h
 * \brief
 * Rate limit clients using a Bloom filter
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
 * Every p seconds all the buckets are multiplied by an aging factor
 * 0 <= a < 1. If a client is querying at a constant rate r the
 * measured value from the hash table r' comes from the sum of the
 * resulting geometric progression, which is p * r / (1 - a). So to
 * calculate the client's actual rate from the value in the hash table,
 * r = r' * (1 - a) / p.
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
 *
 */

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

struct isc_bloomlimit {
	isc_uint32_t bl_size;
	isc_uint32_t bl_hashes;
	isc_uint32_t bl_random;
	isc_uint32_t *bl_table;
};

ISC_LANG_ENDDECLS

#endif /* ISC_BLOOMLIMIT_H */
