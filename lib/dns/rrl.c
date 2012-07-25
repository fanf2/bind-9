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

/* #define ISC_LIST_CHECKINIT */

#include <config.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/netaddr.h>

#include <dns/result.h>
#include <dns/rcode.h>
#include <dns/rdatatype.h>
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
	 * The timestamp is in the future.  That future might result from
	 * re-ordered requests, because we use timestamps on requests
	 * instead of consulting a clock.  Timestamps in the distant future are
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
 * Construct the database key.
 * Use a hash of the DNS query name to save space in the database.
 * Collisions result in legitimate rate limiting responses for one
 * query name also limiting responses for other names to the
 * same client.  This is rare and benign enough given the large
 * space costs compared to keeping the entire name in the database
 * entry or the time costs of dynamic allocation.
 */
static isc_uint32_t
make_key(dns_rrl_t *rrl, dns_rrl_key_t *key, const isc_sockaddr_t *client_addr,
	 dns_rdatatype_t qtype, dns_name_t *tgt_name, dns_rrl_kflags_t kflags)
{
	isc_uint32_t hval;
	int i;

	memset(key, 0, sizeof(*key));
	hval = 0;

	if ((kflags & (DNS_RRL_KFLAG_NXDOMAIN | DNS_RRL_KFLAG_ERROR |
		       DNS_RRL_KFLAG_USED_TCP)) == 0) {
		key->qtype = qtype;
		hval += qtype;
	}

	if (tgt_name != NULL && tgt_name->labels != 0) {
		/*
		 * Ignore the first label of wildcards.
		 */
		if ((tgt_name->attributes & DNS_NAMEATTR_WILDCARD) != 0 &&
		    (i = dns_name_countlabels(tgt_name)) > 1) {
			dns_fixedname_t suffixf;
			dns_name_t *suffix;

			dns_fixedname_init(&suffixf);
			suffix = dns_fixedname_name(&suffixf);
			dns_name_split(tgt_name, i-1, NULL, suffix);
			key->name = dns_name_hashbylabel(suffix, ISC_FALSE);
		} else {
			key->name = dns_name_hashbylabel(tgt_name, ISC_FALSE);
		}
		hval += key->name;
	}

	switch (client_addr->type.sa.sa_family) {
	case AF_INET:
		key->ip[3] = (client_addr->type.sin.sin_addr.s_addr &
			      rrl->ipv4_mask);
		hval = (hval>>31) + (hval<<1) + key->ip[3];
		break;
	case AF_INET6:
		key->kflags |= DNS_RRL_KFLAG_IPV6;
		memcpy(key->ip, &client_addr->type.sin6.sin6_addr,
		       sizeof(key->ip));
		for (i = 0; i < 4; ++i) {
			key->ip[i] &= rrl->ipv6_mask[i];
			hval = (hval>>31) + (hval<<1) + key->ip[i];
		}
		break;
	}

	hval += key->kflags;

	return (hval);
}

/*
 * Search for an entry for a response and optionally create it.
 */
static dns_rrl_entry_t *
get_rrl_entry(dns_rrl_t *rrl, const isc_sockaddr_t *client_addr,
	      dns_rdatatype_t qtype, dns_name_t *tgt_name,
	      dns_rrl_kflags_t kflags, isc_stdtime_t now,
	      isc_boolean_t create)
{
	dns_rrl_key_t key;
	isc_uint32_t hval;
	dns_rrl_hash_t *hash, *old_hash;
	dns_rrl_entry_t *e;
	dns_rrl_bin_t *new_bin, *old_bin;
	int probes, secs, balance;

	hval = make_key(rrl, &key, client_addr, qtype, tgt_name, kflags);

	/*
	 * Look for the entry in the current hash table.
	 */
	hash = rrl->hash;
	new_bin = get_rrl_bin(hash, hval);
	for (e = ISC_LIST_HEAD(*new_bin), probes = 1;
	     e != NULL;
	     e = ISC_LIST_NEXT(e, hlink), ++probes) {
		if (rrl_key_cmp(&e->key, &key)) {
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
			if (rrl_key_cmp(&e->key, &key)) {
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

	if (!create)
		return (NULL);

	/*
	 * The block does not already exist, so create it.
	 * Unroll the first circuit of the loop to cover most cases.
	 * Immediately a new create entry if the oldest is fresh.
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
			if ((e->key.kflags & DNS_RRL_KFLAG_NXDOMAIN) != 0) {
				balance += secs * rrl->nxdomains_per_second;
			} else if ((e->key.kflags & DNS_RRL_KFLAG_ERROR) != 0) {
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
	e->key = key;
	e->last_used = 0;
	rrl_entry_ref(rrl, e, new_bin, probes, now);
	return (e);
}

static inline dns_rrl_result_t
debit_rrl_entry(dns_rrl_t *rrl, dns_rrl_entry_t *e, double qps, double scale,
		const isc_sockaddr_t *client_addr, isc_stdtime_t now,
		isc_boolean_t *old)
{
	int rate, new_rate, *ratep, slip, new_slip, secs, log_secs, min;
	const char *rate_str;
	dns_rrl_entry_t const *credit_e;
	dns_rrl_result_t rrl_result;

	/*
	 * Optionally adjust the rates by the estimated query/second rate.
	 */
	if ((e->key.kflags & DNS_RRL_KFLAG_NXDOMAIN) != 0) {
		rate = rrl->nxdomains_per_second;
		ratep = &rrl->scaled_nxdomains_per_second;
	} else if ((e->key.kflags & DNS_RRL_KFLAG_ERROR) != 0) {
		rate = rrl->errors_per_second;
		ratep = &rrl->scaled_errors_per_second;
	} else {
		rate = rrl->responses_per_second;
		ratep = &rrl->scaled_responses_per_second;
	}
	if (rate == 0)
		return (DNS_RRL_RESULT_OK);

	if (scale < 1.0) {
		/*
		 * The limit for clients that have used TCP is not scaled.
		 */
		credit_e = get_rrl_entry(rrl, client_addr, dns_rdatatype_none,
					 NULL, DNS_RRL_KFLAG_USED_TCP,
					 now, ISC_FALSE);
		if (credit_e != NULL) {
			secs = delta_rrl_time(credit_e->last_used, now);
			if (secs < rrl->window)
				scale = 1.0;
		}
	}
	if (scale < 1.0) {
		new_rate = rate * scale;
		if (new_rate < 1)
			new_rate = 1;
		if (*ratep != new_rate) {
			if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG2)) {
				if ((e->key.kflags &
				     DNS_RRL_KFLAG_NXDOMAIN) != 0) {
					rate_str = "nxdomains-per-second";
				} else if ((e->key.kflags &
					    DNS_RRL_KFLAG_ERROR) != 0) {
					rate_str = "errors-per-second";
				} else {
					rate_str = "responses-per-second";
				}
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
					      DNS_LOGMODULE_REQUEST,
					      DNS_RRL_LOG_DEBUG2,
					      "%d qps scaled %s by %.2f"
					      " from %d to %d",
					      (int)qps, rate_str, scale,
					      rate, new_rate);
			}
			rate = new_rate;
			*ratep = rate;
		}
	}

	min = -rrl->window * rate;

	/*
	 * Treat time jumps into the past as no time.
	 * Treat entries older than the window as if they were just created
	 * Credit other entries.
	 */
	rrl_result = DNS_RRL_RESULT_DROP;
	*old = ISC_FALSE;
	secs = delta_rrl_time(e->last_used, now);
	if (secs <= 0) {
		if (e->responses < 0)
			*old = ISC_TRUE;
	} else {
		/*
		 * Credit tokens earned during elapsed time.
		 */
		if (secs > rrl->window) {
			e->log_secs = DNS_RRL_MAX_LOG_SECS;
			e->responses = rate;
			e->slip_cnt = 0;
		} else {
			e->responses += rate*secs;
			if (e->responses > rate) {
				e->log_secs = DNS_RRL_MAX_LOG_SECS;
				e->responses = rate;
				e->slip_cnt = 0;
			} else if (e->responses <= 0) {
				*old = ISC_TRUE;
			}
		}
		/*
		 * Find the seconds since last log message without overflowing
		 * small counter.
		 * This counter should be reset when an entry is create (or
		 * recycled) and after at least one second without limiting.
		 * It is not necessarily reset when some requests are answered
		 * provided other requests continue to be dropped or slipped.
		 * This can happen when the request rate is just at the limit.
		 */
		log_secs = e->log_secs;
		log_secs += secs;
		if (log_secs > DNS_RRL_MAX_LOG_SECS || log_secs < 0)
			log_secs = DNS_RRL_MAX_LOG_SECS;
		e->log_secs = log_secs;
	}
	e->last_used = now;

	if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG3))
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
			      DNS_LOGMODULE_REQUEST, DNS_RRL_LOG_DEBUG3,
			      "rrl secs=%d  responses=%d", secs, e->responses);

	/*
	 * Debit the entry for this response.
	 */
	if (--e->responses >= 0)
		return (DNS_RRL_RESULT_OK);

	if (e->responses < min)
		e->responses = min;

	/*
	 * Drop this response unless it should leak.
	 */
	slip = rrl->slip;
	if (slip > 2 && scale < 1.0) {
		new_slip *= scale;
		if (new_slip < 2)
			new_slip = 2;
		if (rrl->scaled_slip != new_slip) {
			if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG2))
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
					      DNS_LOGMODULE_REQUEST,
					      DNS_RRL_LOG_DEBUG2,
					      "%d qps scaled slip"
					      " by %.2f from %d to %d",
					      (int)qps, scale,
					      slip, new_slip);
			slip = new_slip;
			rrl->scaled_slip = slip;
		}
	}
	if (slip != 0 && ++e->slip_cnt >= slip) {
		e->slip_cnt = 0;
		return (DNS_RRL_RESULT_SLIP);
	}

	return (rrl_result);
}

/*
 * Build a string for the logs.
 * The caller has already checked to see that this is necessary.
 * The number of responses dropped or slipped is not included in the
 * message, because it would be inaccurate.  There is no log message
 * when an entry is recycled even if some responses have been dropped
 * or slipped.  Each entry would also be 8 bytes larger for counts
 * of dropped and slipped responses.
 */
static void
dns_rrl_log_str(const dns_rrl_t *rrl, dns_rrl_entry_t *e, isc_boolean_t old,
		dns_rdatatype_t qtype, dns_name_t *tgt_name,
		char *ws_buf, int ws_buf_len,
		char *client_buf, int client_buf_len,
		char *tgt_name_buf, int tgt_name_buf_len)
{
	isc_netaddr_t cidr;
	char cidr_buf[ISC_NETADDR_FORMATSIZE];
	char qtype_buf[DNS_RDATATYPE_FORMATSIZE];
	const char *for_str, *for2_str;
	int prefixlen;

	snprintf(ws_buf, ws_buf_len, "%s%s",
		 rrl->log_only ? "would " : "",
		 old ? "continue " : "");

	memset(&cidr, 0, sizeof(cidr));
	if ((e->key.kflags & DNS_RRL_KFLAG_IPV6) == 0) {
		prefixlen = rrl->ipv4_prefixlen;
		cidr.family = AF_INET;
		cidr.type.in.s_addr = e->key.ip[3];
	} else {
		prefixlen = rrl->ipv6_prefixlen;
		cidr.family = AF_INET6;
		memcpy(&cidr.type.in6, e->key.ip, sizeof(cidr.type.in6));
	}
	isc_netaddr_format(&cidr, cidr_buf, sizeof(cidr_buf));

	if (tgt_name == NULL || !dns_name_isabsolute(tgt_name)) {
		for_str = "";
		qtype_buf[0] = '\0';
		for2_str = "";
		tgt_name_buf[0] = '\0';
	} else {
		for_str = " for IN ";
		dns_rdatatype_format(qtype, qtype_buf, sizeof(qtype_buf));
		for2_str = " ";
		dns_name_format(tgt_name, tgt_name_buf, tgt_name_buf_len);
	}

	snprintf(client_buf, client_buf_len, "%s/%d%s%s%s",
		 cidr_buf, prefixlen,
		 for_str, qtype_buf, for2_str);
}

static void
log_sub(int level, dns_rcode_t rcode, const char *log_ws_buf,
	const char *log_client_buf, const char *tgt_name_buf)
{
	const char *err_str;

	if (rcode == dns_rcode_noerror)
		err_str = "";
	else if (rcode == dns_rcode_nxdomain)
		err_str = "NXDOMAIN ";
	else
		err_str = "error ";
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_RRL,
		      DNS_LOGMODULE_REQUEST, level,
		      "%slimiting %sresponses to %s%s",
		      log_ws_buf, err_str,
		      log_client_buf, tgt_name_buf);
}

/*
 * Main rate limit interface.
 */
dns_rrl_result_t
dns_rrl(dns_rrl_t *rrl, const isc_sockaddr_t *client_addr,
	dns_rdataclass_t rdclass, dns_rdatatype_t qtype,
	dns_name_t *tgt_name, dns_rcode_t rcode, isc_stdtime_t now,
	isc_boolean_t wouldlog, isc_boolean_t is_tcp,
	char *log_ws_buf, int log_ws_buf_len,
	char *log_client_buf, int log_client_buf_len,
	char *tgt_name_buf, int tgt_name_buf_len)
{
	dns_rrl_kflags_t kflags;
	dns_rrl_entry_t *e;
	isc_netaddr_t netclient;
	int secs;
	double qps, scale;
	int exempt_match;
	isc_result_t result;
	isc_boolean_t old;
	dns_rrl_result_t rrl_result;

	INSIST(log_ws_buf != NULL && log_ws_buf_len > 0);
	INSIST(log_client_buf != NULL && log_client_buf_len > 0);
	INSIST(tgt_name_buf != NULL && tgt_name_buf_len > 0);

	if (rrl->exempt != NULL) {
		isc_netaddr_fromsockaddr(&netclient, client_addr);
		result = dns_acl_match(&netclient, NULL, rrl->exempt,
				       NULL, &exempt_match, NULL);
		if (result == ISC_R_SUCCESS && exempt_match > 0)
			return DNS_RRL_RESULT_OK;
	}

	LOCK(&rrl->lock);
	if (rrl->qps_scale == 0) {
		qps = 0.0;
		scale = 1.0;
	} else {
		++rrl->qps_responses;
		secs = delta_rrl_time(rrl->qps_time, now);
		if (secs <= 0) {
			qps = rrl->qps;
		} else {
			qps = (1.0*rrl->qps_responses) / secs;
			if (secs >= rrl->window) {
				if (isc_log_wouldlog(dns_lctx,
						     DNS_RRL_LOG_DEBUG3))
					isc_log_write(dns_lctx,
						      DNS_LOGCATEGORY_RRL,
						      DNS_LOGMODULE_REQUEST,
						      DNS_RRL_LOG_DEBUG3,
						      "%d responses/%d seconds"
						      " = %d qps",
						      rrl->qps_responses,
						      secs, (int)qps);
				rrl->qps = qps;
				rrl->qps_responses = 0;
				rrl->qps_time = now;
			} else if (qps < rrl->qps) {
				qps = rrl->qps;
			}
		}
		scale = rrl->qps_scale / qps;
	}

	/*
	 * Notice TCP requests when scaling limits by qps.
	 */
	if (is_tcp) {
		if (scale < 1.0) {
			e = get_rrl_entry(rrl, client_addr, dns_rdatatype_none,
					  NULL, DNS_RRL_KFLAG_USED_TCP,
					  now, ISC_TRUE);
			if (e != NULL) {
				e->responses = 1;
				e->last_used = now;
			}
		}
		UNLOCK(&rrl->lock);
		return (ISC_R_SUCCESS);
	}

	/*
	 * Find the entry and create it if necessary.
	 * If that is impossible, then nothing more can be done
	 */
	if (rcode == dns_rcode_noerror)
		kflags = 0;
	else if (rcode == dns_rcode_nxdomain)
		kflags = DNS_RRL_KFLAG_NXDOMAIN;
	else
		kflags = DNS_RRL_KFLAG_ERROR;
	if (rdclass != dns_rdataclass_in)
		kflags |= DNS_RRL_KFLAG_NOT_IN;
	e = get_rrl_entry(rrl, client_addr, qtype, tgt_name, kflags,
			  now, ISC_TRUE);
	if (e == NULL) {
		UNLOCK(&rrl->lock);
		return (DNS_RRL_RESULT_OK);
	}

	/*
	 * Do not worry about speed or lock with logging this high.
	 */
	if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DEBUG3)) {
		dns_rrl_log_str(rrl, e, old, qtype, tgt_name,
				log_ws_buf, log_ws_buf_len,
				log_client_buf, log_client_buf_len,
				tgt_name_buf, tgt_name_buf_len);
		log_sub(DNS_RRL_LOG_DEBUG3, rcode,
			"possibly ", log_client_buf, tgt_name_buf);
	}

	rrl_result = debit_rrl_entry(rrl, e, qps, scale,
				     client_addr, now, &old);
	if (rrl_result == DNS_RRL_RESULT_OK) {
		UNLOCK(&rrl->lock);
		return (DNS_RRL_RESULT_OK);
	}

	if (wouldlog || (e->log_secs >= DNS_RRL_MAX_LOG_SECS &&
			 isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DROP))) {
		dns_rrl_log_str(rrl, e, old, qtype, tgt_name,
				log_ws_buf, log_ws_buf_len,
				log_client_buf, log_client_buf_len,
				tgt_name_buf, tgt_name_buf_len);
	} else {
		log_ws_buf[0] = '\0';
		log_client_buf[0] = '\0';
		tgt_name_buf[0] = '\0';
	}

	/*
	 * Log occassionally in the rate-limit category,
	 * without holding the lock.
	 */
	if (e->log_secs >= DNS_RRL_MAX_LOG_SECS) {
		e->log_secs = 0;
		UNLOCK(&rrl->lock);
		if (isc_log_wouldlog(dns_lctx, DNS_RRL_LOG_DROP))
			log_sub(DNS_RRL_LOG_DROP, rcode,
				log_ws_buf, log_client_buf, tgt_name_buf);
	} else {
		UNLOCK(&rrl->lock);
	}
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

	if (rrl->exempt != NULL)
		dns_acl_detach(&rrl->exempt);

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
