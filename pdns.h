/*
 * Copyright (c) 2014-2020 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PDNS_H_INCLUDED
#define PDNS_H_INCLUDED 1

#include <jansson.h>
#include "netio.h"

/* main is the primary jansson library object from a json_loadb().
 * all the other fields in this structure will point inside main, as
 * borrowed references, so const.  main must be deallocated
 * by json_decref() which then invalidates all the other fields.
 *
 * cof_obj points to the object that contains time_first...num_results.
 * If not using SAF encapulation, then cof_obj points to main.
 * If using SAF encapulation, then saf_cond, saf_msg, and saf_obj are
 * parsed from main and cof_obj is repointed to saf_obj.
 */
struct pdns_json {
	json_t *main;
	const json_t *cof_obj, *saf_obj, *saf_cond, *saf_msg,
		*time_first, *time_last, *zone_first, *zone_last,
		*bailiwick, *rrname, *rrtype, *rdata,
		*count, *num_results;
};

struct pdns_tuple {
	struct pdns_json  obj;
	u_long		  time_first, time_last, zone_first, zone_last;
	const char	 *bailiwick, *rrname, *rrtype, *rdata, *cond, *msg;
	json_int_t	  count, num_results;
};
typedef struct pdns_tuple *pdns_tuple_t;
typedef const struct pdns_tuple *pdns_tuple_ct;

struct pdns_fence {
	u_long	first_after, first_before, last_after, last_before;
};
typedef struct pdns_fence pdns_fence_t;
typedef const struct pdns_fence *pdns_fence_ct;

struct pdns_system {
	/* name of this pdns system, as specifiable by the user. */
	const char	*name;

	/* default URL to reach this pdns API endpoint.  May be overridden. */
	const char	*base_url;

	/* what encapsulation does this system speak? */
	encap_e		encap;

	/* what's our downgrade path if this system doesn't function
	 * (respond positively to a probe)?  may be NULL if there is no
	 * downgrade available.
	 */
	const struct pdns_system *  (*next)(void);

	/* to probe if this system reachable and functional. will be
	 * NULL whenever "next" (see above) is NULL.
	 */
	bool		(*probe)(void);

	/* start creating a URL corresponding to a command-path string.
	 * first argument is the input URL path.
	 * second is an output parameter pointing to the separator character
	 * (? or &) that the caller should use between any further URL
	 * parameters.  May be NULL if the caller doesn't care.
	 * the third argument is search parameters.
	 */
	char *		(*url)(const char *, char *, qparam_ct,
			       pdns_fence_ct, bool);

	/* send a request for info, such as quota information.
	 * may be NULL if info requests are not supported by this pDNS system.
	 */
	void		(*info)(void);

	/* add authentication information to the fetch request being created.
	 * may be NULL if auth is not needed by this pDNS system.
	 */
	void		(*auth)(fetch_t);

	/* map a non-200 HTTP rcode from a fetch to an error indicator. */
	const char *	(*status)(fetch_t);

	/* verify that the specified verb is supported by this pdns system.
	 * Returns NULL if supported; otherwise returns a static error message.
	 */
	const char *	(*verb_ok)(const char *, qparam_ct);

	/* set a configuration key-value pair.  Returns NULL if ok;
	 * otherwise returns a static error message.
	 */
	const char *	(*setval)(const char *, const char *);

	/* check if ready with enough config settings to try API queries.
	 * Returns NULL if ready; otherwise returns a static error message.
	 */
	const char *	(*ready)(void);

	/* drop heap storage. */
	void		(*destroy)(void);
};
typedef const struct pdns_system *pdns_system_ct;

typedef void (*present_t)(pdns_tuple_ct, const char *, size_t, writer_t);

/* a verb is a specific type of request.  See struct pdns_system
 * verb_ok() for that function that verifies if the verb and the options
 * provided is supported by that pDNS system.
 */
struct verb {
	const char	*name;
	const char	*url_fragment;

	/* review the command line options for constraints being met.
	 * Returns NULL if ok; otherwise returns a static error message.
	 */
	const char *	(*ok)(void);

	/* formatter function for each presentation format */
	present_t	text, json, csv;
};
typedef const struct verb *verb_ct;

/* a query mode. not all pdns systems support all of these. */
typedef enum { no_mode = 0, rrset_mode, name_mode, ip_mode,
	       raw_rrset_mode, raw_name_mode } mode_e;

/* query parameters descriptor. */
struct qdesc {
	mode_e	mode;
	char	*thing;
	char	*rrtype;
	char	*bailiwick;
	char	*pfxlen;
};
typedef struct qdesc *qdesc_t;
typedef const struct qdesc *qdesc_ct;

bool pprint_json(const char *, size_t, FILE *);
void present_json_lookup(pdns_tuple_ct, const char *, size_t, writer_t);
void present_json_summarize(pdns_tuple_ct, const char *, size_t, writer_t);
void present_text_lookup(pdns_tuple_ct, const char *, size_t, writer_t);
void present_csv_lookup(pdns_tuple_ct, const char *, size_t, writer_t);
void present_text_summarize(pdns_tuple_ct, const char *, size_t, writer_t);
void present_csv_summarize(pdns_tuple_ct, const char *, size_t, writer_t);
const char *tuple_make(pdns_tuple_t, const char *, size_t);
void tuple_unmake(pdns_tuple_t);
int data_blob(query_t, const char *, size_t);
void pdns_probe(void);
void pick_system(const char *, const char *);
void read_config(const char *cf);

/* Some HTTP status codes we handle specifically */
#define HTTP_OK		   200
#define HTTP_NOT_FOUND	   404

#if WANT_PDNS_DNSDB
#include "pdns_dnsdb.h"
#endif
#if WANT_PDNS_CIRCL
#include "pdns_circl.h"
#endif

#endif /*PDNS_H_INCLUDED*/
