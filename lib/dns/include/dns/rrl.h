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

#ifndef DNS_RRL_H
#define DNS_RRL_H 1

/*
 * Rate limit DNS responses.
 */

#include <isc/lang.h>

#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/types.h>

ISC_LANG_BEGINDECLS


#define DNS_RRL_LOG_FAIL	ISC_LOG_WARNING
#define DNS_RRL_LOG_INIT	ISC_LOG_INFO
#define DNS_RRL_LOG_REPEAT	ISC_LOG_DEBUG(1)
#define DNS_RRL_LOG_DEBUG1	ISC_LOG_DEBUG(3)
#define DNS_RRL_LOG_DEBUG2	ISC_LOG_DEBUG(4)
#define DNS_RRL_LOG_DEBUG3	ISC_LOG_DEBUG(5)


typedef struct dns_rrl_hash dns_rrl_hash_t;

/*
 * A rate limit bucket key.
 */
typedef struct dns_rrl_key dns_rrl_key_t;
struct dns_rrl_key {
	isc_uint32_t	ip[4];		/* IP address */
	unsigned int	name;		/* hash of DNS name */
	isc_uint8_t	type;		/* query type */
	isc_uint8_t	flags;
# define DNS_RRL_FLAG_ERROR	0x01
# define DNS_RRL_FLAG_NOT_IN	0x02
};

/*
 * A rate-limit entry.
 */
typedef struct dns_rrl_entry dns_rrl_entry_t;
typedef ISC_LIST(dns_rrl_entry_t) dns_rrl_bin_t;
struct dns_rrl_entry {
	ISC_LINK(dns_rrl_entry_t) lru;
	ISC_LINK(dns_rrl_entry_t) hlink;
	dns_rrl_bin_t	*bin;
	isc_stdtime_t	last_used;
	isc_int32_t	responses;
# define DNS_RRL_MAX_WINDOW	600
# define DNS_RRL_MAX_RATE	(ISC_INT32_MAX / DNS_RRL_MAX_WINDOW)
	dns_rrl_key_t	key;
	isc_uint8_t	slip_cnt;
};

/*
 * A hash table of rate-limit entries.
 */
struct dns_rrl_hash {
	isc_stdtime_t	check_time;
	int		length;
	dns_rrl_bin_t	bins[1];
};

/*
 * A block of rate-limit entries.
 */
typedef struct dns_rrl_block dns_rrl_block_t;
struct dns_rrl_block {
	ISC_LINK(dns_rrl_block_t) link;
	int		size;
	dns_rrl_entry_t	entries[1];
};

/*
 * Per-view query rate limit parameters and a pointer to database.
 */
typedef struct dns_rrl dns_rrl_t;
struct dns_rrl {
	isc_mutex_t	lock;
	isc_mem_t	*mctx;

	isc_boolean_t	log_only;
	int		responses_per_second;
	int		errors_per_second;
	int		window;
	int		slip;
	int		max_entries;

	int		num_entries;

	unsigned int	probes;
	unsigned int	searches;

	ISC_LIST(dns_rrl_block_t) blocks;
	ISC_LIST(dns_rrl_entry_t) lru;

	dns_rrl_hash_t	*hash;
	dns_rrl_hash_t	*old_hash;

	int		ipv4_prefixlen;
	isc_uint32_t	ipv4_mask;
	int		ipv6_prefixlen;
	isc_uint32_t	ipv6_mask[4];
};

typedef enum {
	DNS_RRL_RESULT_OK,
	DNS_RRL_RESULT_NEW_DROP,
	DNS_RRL_RESULT_OLD_DROP,
	DNS_RRL_RESULT_SLIP,
} dns_rrl_result_t;

dns_rrl_result_t
dns_rrl(dns_rrl_t *rrl, const isc_sockaddr_t *client_addr,
	dns_rdataclass_t class, dns_rdatatype_t qtype, dns_name_t *fname,
	isc_boolean_t is_error, isc_stdtime_t now);

void
dns_rrl_view_destroy(dns_view_t *view);

isc_result_t
dns_rrl_init(dns_rrl_t **rrlp, dns_view_t *view, int min_entries);

ISC_LANG_ENDDECLS

#endif /* DNS_RRL_H */
