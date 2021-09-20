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

#ifndef NETIO_H_INCLUDED
#define NETIO_H_INCLUDED 1

#include <stdbool.h>
#include <curl/curl.h>

/* encapsulation protocol.  ruminate, DNBDB APIv1 and CIRCL use encap_cof. */
typedef enum { encap_cof = 0, encap_saf } encap_e;

/* official SAF condition values, plus sc_init, sc_we_limited, and sc_missing.
 */
typedef enum {
	sc_init = 0,	 /* initial condition */
	/* official */
	sc_begin, sc_ongoing, sc_succeeded, sc_limited, sc_failed,
	sc_we_limited,	 /* we noticed we hit the output limit */
	sc_missing	 /* cond was missing at end of input stream */
} saf_cond_e;

/* search parameters, per query and globally. */
struct qparam {
	u_long		after;
	u_long		before;
	long		query_limit;
	/* actually set on the command line or in OPTIONS */
	long		explicit_output_limit;
	/* inferred and used in output code */
	long		output_limit;
	long		offset;
	bool		complete;
	bool		gravel;
};
typedef struct qparam *qparam_t;
typedef const struct qparam *qparam_ct;

/* one API fetch; several may be needed for complex (multitype) queries. */
struct fetch {
	struct fetch	*next;
	struct query	*query;
	CURL		*easy;
	struct curl_slist  *hdrs;
	char		*url;
	char		*buf;
	size_t		len;
	long		rcode;
	bool		stopped;
};
typedef struct fetch *fetch_t;

/* one query; one per invocation (or per batch line.) */
struct query {
	struct query	*next;
	struct fetch	*fetches;
	struct writer	*writer;
	struct qparam	params;
	char		*descrip;
	mode_e		mode;
	bool		multitype;
	/* invariant: (status == NULL) == (writer == NULL) */
	char		*status;
	char		*message;
	bool		hdr_sent;
	saf_cond_e	saf_cond;
	char		*saf_msg;
};
typedef struct query *query_t;

typedef void (*ps_user_t)(struct writer *);

/* one output stream, having one or several queries merging into it. */
struct writer {
	struct writer	*next;
	struct query	*queries;
	struct query	*active;
	FILE		*sort_stdin;
	FILE		*sort_stdout;
	pid_t		sort_pid;
	bool		sort_killed;
	bool		csv_headerp;
	bool		meta_query;
	char		*ps_buf;
	size_t		ps_len;
	ps_user_t	ps_user;
	long		output_limit;
	int		count;
};
typedef struct writer *writer_t;

void make_curl(void);
void unmake_curl(void);
fetch_t create_fetch(query_t, char *);
writer_t writer_init(long, ps_user_t, bool);
void ps_stdout(writer_t);
void query_status(query_t, const char *, const char *);
size_t writer_func(char *ptr, size_t size, size_t nmemb, void *blob);
void writer_fini(writer_t);
void unmake_writers(void);
void io_engine(int);
char *escape(const char *);

#endif /*NETIO_H_INCLUDED*/
