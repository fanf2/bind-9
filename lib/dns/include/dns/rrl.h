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


/*
 * Memory allocation or other failures.
 */
#define DNS_RRL_LOG_FAIL	ISC_LOG_WARNING
/*
 * dropped or slipped responses.
 */
#define DNS_RRL_LOG_DROP	ISC_LOG_INFO
/*
 * Major events in dropping or slipping.
 */
#define DNS_RRL_LOG_DEBUG1	ISC_LOG_DEBUG(3)
/*
 * Limit computations.
 */
#define DNS_RRL_LOG_DEBUG2	ISC_LOG_DEBUG(4)
/*
 * Less interesting.
 */
#define DNS_RRL_LOG_DEBUG3	ISC_LOG_DEBUG(9)


#define DNS_RRL_LOG_ERR_LEN	64
#define DNS_RRL_LOG_BUF_LEN	(sizeof("would continue limiting") +	\
				 DNS_RRL_LOG_ERR_LEN +			\
				 sizeof(" responses to ") +		\
				 ISC_NETADDR_FORMATSIZE +		\
				 sizeof("/128 for IN ") +		\
				 DNS_RDATATYPE_FORMATSIZE +		\
				 DNS_NAME_FORMATSIZE)


typedef struct dns_rrl_hash dns_rrl_hash_t;

/*
 * Response types.
 */
typedef enum {
	DNS_RRL_RTYPE_FREE,
	DNS_RRL_RTYPE_QUERY,
	DNS_RRL_RTYPE_NXDOMAIN,
	DNS_RRL_RTYPE_ERROR,
	DNS_RRL_RTYPE_ALL,
	DNS_RRL_RTYPE_TCP,
} dns_rrl_rtype_t;

/*
 * A rate limit bucket key.
 * This should be small to limit the total size of the database.
 */
typedef struct dns_rrl_key dns_rrl_key_t;
struct dns_rrl_key {
	isc_uint32_t	    ip[4];
	isc_uint32_t	    qname_hash;
	dns_rdatatype_t	    qtype;
	dns_rrl_rtype_t	    rtype   :3;
	isc_boolean_t	    qclass  :3;
	isc_boolean_t	    ipv6    :1;
};

/*
 * A rate-limit entry.
 * This should be small to limit the total size of the database.
 * With gcc on ARM, the key should have __attribute((__packed__)) to
 *	avoid padding to a multiple of 8 bytes.
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
	unsigned int	slip_cnt    :4;
# define DNS_RRL_MAX_SLIP	10
	unsigned int	log_secs    :10;
# define DNS_RRL_MAX_LOG_SECS	600
# define DNS_RRL_STOP_LOG_SECS	60
	isc_boolean_t	logged	    :1;
	unsigned int	log_qname   :8;
# define DNS_RRL_NUM_QNAMES	256
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
 * A rate limited qname buffers.
 */
typedef struct dns_rrl_qname_buf dns_rrl_qname_buf_t;
struct dns_rrl_qname_buf {
	ISC_LINK(dns_rrl_qname_buf_t) link;
	const dns_rrl_entry_t *e;
	unsigned int	    index;
	dns_fixedname_t	    qname;
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
	int		nxdomains_per_second;
	int		all_per_second;
	int		window;
	int		slip;
	double		qps_scale;
	int		max_entries;

	dns_acl_t	*exempt;

	int		num_entries;

	int		qps_responses;
	isc_stdtime_t	qps_time;
	double		qps;
	int		scaled_responses_per_second;
	int		scaled_errors_per_second;
	int		scaled_nxdomains_per_second;
	int		scaled_all_per_second;
	int		scaled_slip;

	isc_stdtime_t	prune_time;

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

	dns_rrl_entry_t	*log_ended;
	ISC_LIST(dns_rrl_qname_buf_t) qname_free;
	int		num_qnames;
	dns_rrl_qname_buf_t *qnames[DNS_RRL_NUM_QNAMES];
};

typedef enum {
	DNS_RRL_RESULT_OK,
	DNS_RRL_RESULT_DROP,
	DNS_RRL_RESULT_SLIP,
} dns_rrl_result_t;

dns_rrl_result_t
dns_rrl(dns_view_t *view,
	const isc_sockaddr_t *client_addr, isc_boolean_t is_tcp,
	dns_rdataclass_t rdclass, dns_rdatatype_t qtype,
	dns_name_t *qname, dns_rcode_t rcode, isc_stdtime_t now,
	isc_boolean_t wouldlog, char *log_buf, unsigned int log_buf_len);

void
dns_rrl_view_destroy(dns_view_t *view);

isc_result_t
dns_rrl_init(dns_rrl_t **rrlp, dns_view_t *view, int min_entries);

ISC_LANG_ENDDECLS

#endif /* DNS_RRL_H */
