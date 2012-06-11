/*
 * Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id$ */

/*! \file */

/*
 * Rate limit DNS responses.
 */

#define ISC_LIST_CHECKINIT

#include <config.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/netaddr.h>

#include <dns/result.h>
#include <dns/log.h>
#include <dns/rrl.h>
#include <dns/view.h>


/*
 * Get a modulus for a hash function that is tolerably likely to be
 * relatively prime to most inputs.  Of course, we get a prime for for initial
 * values not larger than the square of the last prime.  We often get a prime
 * after that.
 * This works well in practice for hash tables up to at least 100
 * times the square of the last prime and better than a multiplicative hash.
 */
static int
hash_divisor(unsigned int initial) {
	static isc_uint16_t primes[] = {
		  3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,
		 43,  47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,
#if 0
		101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
		163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
		229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
		293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367,
		373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
		443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
		521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
		601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
		673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
		757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
		839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
		929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,1009,
#endif
	};
	int divisions, tries;
	unsigned int result;
	isc_uint16_t *pp, p;

	result = initial;

	if (primes[sizeof(primes)/sizeof(primes[0])-1] >= result) {
		pp = primes;
		while (*pp < result)
			++pp;
		return (*pp);
	}

	if ((result & 1) == 0)
		++result;

	divisions = 0;
	tries = 1;
	pp = primes;
	do {
		p = *pp++;
		++divisions;
		if ((result % p) == 0) {
			++tries;
			result += 2;
			pp = primes;
		}
	} while (pp < &primes[sizeof(primes)/sizeof(primes[0])]);

	if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG2))
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
			      DNS_LOGMODULE_REQUEST, DNS_RRL_LOG_DEBUG2,
			      "%d hash_divisor() divisions in %d tries"
			      " to get %d from %d",
			      divisions, tries, result, initial);

	return (result);
}

/*
 * Convert a timestamp to a number of seconds in the past.
 */
static inline int
delta_rrl_time(isc_stdtime_t ts, isc_stdtime_t now) {
	int delta;

	delta = now - ts;
	if (delta >= 0)
		return (delta);
	/*
	 * Timestamps in the near future might result from re-ordered
	 * requests, because we use timestamps on requests instead of
	 * consulting a clock.  Timestamps in the distant future are
	 * assumed to result from clock changes.
	 */
	if (delta < -5)
		return (now);
	return (0);
}

static isc_result_t
add_rrl_entries(dns_rrl_t *rrl, int new) {
	unsigned int bsize;
	dns_rrl_block_t *b;
	dns_rrl_entry_t *e;
	double rate;
	int i;

	if (rrl->num_entries+new >= rrl->max_entries && rrl->max_entries != 0) {
		if (rrl->num_entries >= rrl->max_entries)
			return (ISC_R_SUCCESS);
		new = rrl->max_entries - rrl->num_entries;
		if (new <= 0)
			return (ISC_R_NOMEMORY);
	}

	if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG1) &&
	    rrl->hash != NULL) {
		rate = rrl->probes;
		if (rrl->searches != 0)
			rate /= rrl->searches;
		if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG1))
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
				      DNS_LOGMODULE_REQUEST,
				      DNS_RRL_LOG_DEBUG1,
				      "increase from %d to %d RRL entries with"
				      " %d bins; average search length %.1f",
				      rrl->num_entries, rrl->num_entries+new,
				      rrl->hash->length, rate);
	}

	bsize = sizeof(dns_rrl_block_t) + (new-1)*sizeof(dns_rrl_entry_t);
	b = isc_mem_get(rrl->mctx, bsize);
	if (b == NULL) {
		if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_FAIL))
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
				      DNS_LOGMODULE_REQUEST, DNS_RRL_LOG_FAIL,
				      "isc_mem_get(%d bytes) failed for"
				      " query rate limiting entries",
				      bsize);
		return (ISC_R_NOMEMORY);
	}
	memset(b, 0, bsize);
	b->size = bsize;

	for (i = 0, e = b->entries; i < new; ++i, ++e) {
		ISC_LINK_INIT(e, hlink);
		ISC_LIST_INITANDAPPEND(rrl->lru, e, lru);
	}
	rrl->num_entries += new;
	ISC_LIST_INITANDAPPEND(rrl->blocks, b, link);

	return (ISC_R_SUCCESS);
}

static inline dns_rrl_bin_t *
get_rrl_bin(dns_rrl_hash_t *hash, unsigned int hval) {
	return (&hash->bins[hval % hash->length]);
}

static void
free_old_hash(dns_rrl_t *rrl) {
	dns_rrl_hash_t *old_hash;
	dns_rrl_bin_t *old_bin;
	dns_rrl_entry_t *e;

	old_hash = rrl->old_hash;
	for (old_bin = &old_hash->bins[0];
	     old_bin < &old_hash->bins[old_hash->length];
	     ++old_bin) {
		while ((e = ISC_LIST_HEAD(*old_bin)) != NULL) {
			ISC_LIST_UNLINK(*e->bin, e, hlink);
			e->bin = NULL;
		}
	}

	isc_mem_put(rrl->mctx, old_hash,
		    sizeof(*old_hash)
		    + (old_hash->length-1)*sizeof(old_hash->bins[0]));
	rrl->old_hash = NULL;
}

static isc_result_t
expand_rrl_hash(dns_rrl_t *rrl, isc_stdtime_t now) {
	dns_rrl_hash_t *hash;
	int old_bins, new_bins, hsize;
	double rate;

	if (rrl->old_hash != NULL)
		free_old_hash(rrl);

	/*
	 * Most searches fail and so go to the end of the chain.
	 * Use a small hash table load factor.
	 */
	old_bins = (rrl->hash == NULL) ? 0 : rrl->hash->length;
	new_bins = old_bins/8 + old_bins;
	if (new_bins < rrl->num_entries)
		new_bins = rrl->num_entries;
	new_bins = hash_divisor(new_bins);

	hsize = sizeof(dns_rrl_hash_t) + (new_bins-1)*sizeof(hash->bins[0]);
	hash = isc_mem_get(rrl->mctx, hsize);
	if (hash == NULL) {
		if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_FAIL)) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
				      DNS_LOGMODULE_REQUEST, DNS_RRL_LOG_FAIL,
				      "isc_mem_get(%d bytes) failed for"
				      " a query rate limiting hash table",
				      hsize);
		}
		return (ISC_R_NOMEMORY);
	}
	memset(hash, 0, hsize);
	hash->length = new_bins;

	if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG1) && old_bins != 0) {
		rate = rrl->probes;
		if (rrl->searches != 0)
			rate /= rrl->searches;
		if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG1))
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
				      DNS_LOGMODULE_REQUEST,
				      DNS_RRL_LOG_DEBUG1,
				      "increase from %d to %d RRL bins for"
				      " %d entries; average search length %.1f",
				      old_bins, new_bins, rrl->num_entries,
				      rate);
	}

	rrl->old_hash = rrl->hash;
	if (rrl->old_hash != NULL)
		rrl->old_hash->check_time = now;
	rrl->hash = hash;

	return (ISC_R_SUCCESS);
}

static void
rrl_entry_ref(dns_rrl_t *rrl, dns_rrl_entry_t *e, dns_rrl_bin_t *new_bin,
	      int probes, isc_stdtime_t now)
{
	/*
	 * Make the entry most recently used.
	 */
	if (ISC_LIST_HEAD(rrl->lru) != e) {
		ISC_LIST_UNLINK(rrl->lru, e, lru);
		ISC_LIST_PREPEND(rrl->lru, e, lru);
	}

	/*
	 * Move the entry to the head of its hash chain.
	 */
	if (ISC_LIST_HEAD(*new_bin) != e) {
		if (e->bin != NULL)
			ISC_LIST_UNLINK(*e->bin, e, hlink);
		ISC_LIST_PREPEND(*new_bin, e, hlink);
		e->bin = new_bin;
	}

	/*
	 * Expand the hash table if it is time and necessary.
	 * This will leave the newly referenced entry in a chain in the
	 * old hash table.  It will migrate to the new hash table the next
	 * time it is used or be cut loose when the old hash table is destroyed.
	 */
	rrl->probes += probes;
	++rrl->searches;
	if (rrl->searches > 100 &&
	    delta_rrl_time(rrl->hash->check_time, now) >= 10) {
		if (rrl->probes/rrl->searches > 2)
			expand_rrl_hash(rrl, now);
		rrl->hash->check_time = now;
		rrl->probes = 0;
		rrl->searches = 0;
	}
}

static inline isc_boolean_t
rrl_key_cmp(const dns_rrl_key_t *a, const dns_rrl_key_t *b) {
	return (memcmp(a, b, sizeof(dns_rrl_key_t)) == 0 ? ISC_TRUE : ISC_FALSE);
}

/*
 * Get an entry for a response.
 */
static dns_rrl_entry_t *
get_rrl_entry(dns_rrl_t *rrl, const dns_rrl_key_t *key, isc_uint32_t hval,
	      isc_stdtime_t now)
{
	dns_rrl_hash_t *hash, *old_hash;
	dns_rrl_entry_t *e;
	dns_rrl_bin_t *new_bin, *old_bin;
	int probes, secs, balance;

	/*
	 * Look for the entry in the current hash table.
	 */
	hash = rrl->hash;
	new_bin = get_rrl_bin(hash, hval);
	for (e = ISC_LIST_HEAD(*new_bin), probes = 1;
	     e != NULL;
	     e = ISC_LIST_NEXT(e, hlink), ++probes) {
		if (rrl_key_cmp(&e->key, key)) {
			rrl_entry_ref(rrl, e, new_bin, probes, now);
			return (e);
		}
	}

	/*
	 * Look in the old hash table if we did not find the entry.
	 */
	old_hash = rrl->old_hash;
	if (old_hash != NULL) {
		old_bin = get_rrl_bin(old_hash, hval);
		for (e = ISC_LIST_HEAD(*old_bin);
		     e != NULL;
		     e = ISC_LIST_NEXT(e, hlink)) {
			if (rrl_key_cmp(&e->key, key)) {
				rrl_entry_ref(rrl, e, new_bin, probes, now);
				return (e);
			}
		}

		/*
		 * Discard prevous hash table when its entries are all old.
		 */
		if (delta_rrl_time(old_hash->check_time, now) > rrl->window)
			free_old_hash(rrl);
	}

	/*
	 * The block does not already exist, so create it.
	 * Unroll the first circuit of the loop to cover most cases.
	 * Immediately create entries more if the oldest is fresh.
	 * Preserve penalized entries.
	 * Try to make more entries if none are idle.
	 * Steal the oldest entry if we cannot make more.
	 */
	e = ISC_LIST_TAIL(rrl->lru);
	secs = delta_rrl_time(e->last_used, now);
	if (secs <= rrl->window) {
		for (;;) {
			if (secs <= 1) {
				add_rrl_entries(rrl,
						ISC_MIN((rrl->num_entries+1)/2,
							1000));
				e = ISC_LIST_TAIL(rrl->lru);
				break;
			}
			balance = e->responses;
			if (balance >= 0)
				break;
			if ((e->key.flags & DNS_RRL_FLAG_ERROR) != 0) {
				balance += secs * rrl->errors_per_second;
			} else {
				balance += secs * rrl->responses_per_second;
			}
			if (balance >= 0)
				break;

			e = e->lru.prev;
			if (e == NULL) {
				add_rrl_entries(rrl,
						ISC_MIN((rrl->num_entries+1)/2,
							1000));
				e = ISC_LIST_TAIL(rrl->lru);
				break;
			}
			secs = delta_rrl_time(e->last_used, now);
		}
	}
	e->key = *key;
	e->last_used = 0;
	e->slip_cnt = 0;
	rrl_entry_ref(rrl, e, new_bin, probes, now);
	return (e);
}

static dns_rrl_result_t
inc_rrl_entry(dns_rrl_t *rrl, dns_rrl_entry_t *e, isc_stdtime_t now) {
	int rate, secs, min;
	dns_rrl_result_t result;

	if ((e->key.flags & DNS_RRL_FLAG_ERROR) != 0) {
		rate = rrl->errors_per_second;
	} else {
		rate = rrl->responses_per_second;
	}
	if (rate == 0)
		return (DNS_RRL_RESULT_OK);

	/*
	 * Treat time jumps into the past as no time.
	 * Treat entries older than the window as if they were just created
	 * without overflow.
	 * Credit other entries.
	 */
	result = DNS_RRL_RESULT_NEW_DROP;
	secs = delta_rrl_time(e->last_used, now);
	if (secs <= 0) {
		secs = 0;
		if (e->responses < 0)
			result = DNS_RRL_RESULT_OLD_DROP;
	} else if (secs > rrl->window) {
		e->responses = rate;
	} else {
		e->responses += rate*secs;
		if (e->responses > rate)
			e->responses = rate;
		if (e->responses <= 0)
			result = DNS_RRL_RESULT_OLD_DROP;
	}
	e->last_used = now;

#if 0
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
		      DNS_LOGMODULE_REQUEST, DNS_RRL_LOG_DEBUG3,
		      "rrl secs=%d  responses=%d", secs, e->responses);
#endif
	if (--e->responses >= 0) {
		e->slip_cnt = 0;
		return (DNS_RRL_RESULT_OK);
	}

	min = -rrl->window * rate;
	if (e->responses < min)
		e->responses = min;

	/*
	 * Drop this response unless it should leak.
	 */
	if (rrl->slip != 0 && ++e->slip_cnt >= rrl->slip) {
		e->slip_cnt = 0;
		return (DNS_RRL_RESULT_SLIP);
	}

	return (result);
}

dns_rrl_result_t
dns_rrl(dns_rrl_t *rrl, const isc_sockaddr_t *client_addr,
	dns_rdataclass_t class, dns_rdatatype_t qtype, dns_name_t *fname,
	isc_boolean_t is_error, isc_stdtime_t now)
{
	dns_rrl_key_t key;
	isc_uint32_t hval;
	dns_rrl_entry_t *e;
	dns_rrl_result_t rrl_result;
	int i;

	/*
	 * Construct the database key.
	 * Use a hash of the DNS query name to save space in the database.
	 * Collisions result in legitimate rate limiting responses for one
	 * query name also limiting responses for other names to the
	 * same client.  This is rare and benign enough given the large
	 * space costs compared to keeping the entire name in the database
	 * entry or the time costs of dynamic allocation.
	 */
	memset(&key, 0, sizeof(key));
	key.type = qtype;
	hval = qtype;
	if (fname != NULL && fname->labels != 0) {
		/*
		 * Ignore the first label of wildcards.
		 */
		if ((fname->attributes & DNS_NAMEATTR_WILDCARD) != 0 &&
		    (i = dns_name_countlabels(fname)) > 1) {
			dns_fixedname_t suffixf;
			dns_name_t *suffix;

			dns_fixedname_init(&suffixf);
			suffix = dns_fixedname_name(&suffixf);
			dns_name_split(fname, i-1, NULL, suffix);
			key.name = dns_name_hashbylabel(suffix, ISC_FALSE);
		} else {
			key.name = dns_name_hashbylabel(fname, ISC_FALSE);
		}
		hval += key.name;
	}
	switch (client_addr->type.sa.sa_family) {
	case AF_INET:
		key.ip[3] = (client_addr->type.sin.sin_addr.s_addr &
			     rrl->ipv4_mask);
		hval = (hval>>31) + (hval<<1) + key.ip[3];
		break;
	case AF_INET6:
		memcpy(key.ip, &client_addr->type.sin6.sin6_addr,
		       sizeof(key.ip));
		for (i = 0; i < 4; ++i) {
			key.ip[i] &= rrl->ipv6_mask[i];
			hval = (hval>>31) + (hval<<1) + key.ip[i];
		}
		break;
	}
	if (is_error)
		key.flags |= DNS_RRL_FLAG_ERROR;
	if (class != dns_rdataclass_in)
		key.flags |= DNS_RRL_FLAG_NOT_IN;
	hval += key.flags;

	LOCK(&rrl->lock);

	/*
	 * Find the entry and create it if necessary.
	 * If that is impossible, then there is nothing our caller can do.
	 */
	e = get_rrl_entry(rrl, &key, hval, now);
	if (e == NULL) {
		UNLOCK(&rrl->lock);
		return (DNS_RRL_RESULT_OK);
	}

	rrl_result = inc_rrl_entry(rrl, e, now);

	UNLOCK(&rrl->lock);
	return (rrl_result);
}

void
dns_rrl_view_destroy(dns_view_t *view) {
	dns_rrl_t *rrl;
	dns_rrl_block_t *b;
	dns_rrl_hash_t *h;

	rrl = view->rrl;
	if (rrl == NULL)
		return;
	view->rrl = NULL;

	/*
	 * Assume the caller takes care of locking the view and anything else.
	 */
	DESTROYLOCK(&rrl->lock);

	while (!ISC_LIST_EMPTY(rrl->blocks)) {
		b = ISC_LIST_HEAD(rrl->blocks);
		ISC_LIST_UNLINK(rrl->blocks, b, link);
		isc_mem_put(rrl->mctx, b, b->size);
	}

	h = rrl->hash;
	if (h != NULL)
		isc_mem_put(rrl->mctx, h,
			    sizeof(*h)+(h->length-1)*sizeof(h->bins[0]));

	h = rrl->old_hash;
	if (h != NULL)
		isc_mem_put(rrl->mctx, h,
			    sizeof(*h)+(h->length-1)*sizeof(h->bins[0]));

	isc_mem_put(rrl->mctx, rrl, sizeof(*rrl));
}

isc_result_t
dns_rrl_init(dns_rrl_t **rrlp, dns_view_t *view, int min_entries) {
	dns_rrl_t *rrl;
	isc_result_t result;

	*rrlp = NULL;

	rrl = isc_mem_get(view->mctx, sizeof(*rrl));
	if (rrl == NULL)
		return (ISC_R_NOMEMORY);
	memset(rrl, 0, sizeof(*rrl));
	rrl->mctx = view->mctx;
	result = isc_mutex_init(&rrl->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(view->mctx, rrl, sizeof(*rrl));
		return (result);
	}

	view->rrl = rrl;

	result = add_rrl_entries(rrl, min_entries);
	if (result != ISC_R_SUCCESS) {
		dns_rrl_view_destroy(view);
		return (result);
	}
	result = expand_rrl_hash(rrl, 0);
	if (result != ISC_R_SUCCESS) {
		dns_rrl_view_destroy(view);
		return (result);
	}

	*rrlp = rrl;
	return (ISC_R_SUCCESS);
}
