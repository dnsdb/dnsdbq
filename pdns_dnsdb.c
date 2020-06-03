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

#if WANT_PDNS_DNSDB

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>

#include "defs.h"
#include "pdns.h"
#include "pdns_dnsdb.h"
#include "time.h"
#include "globals.h"

/* types. */

struct rate_json {
	json_t	*main,
		*reset, *expires, *limit, *remaining,
		*burst_size, *burst_window, *results_max,
		*offset_max;
};

struct rateval {
	enum {
		rk_naught = 0,		/* not present. */
		rk_na,			/* "n/a". */
		rk_unlimited,		/* "unlimited". */
		rk_int			/* some integer in as_int. */
	} rk;
	u_long	as_int;		/* only for rk == rk_int. */
};
typedef struct rateval *rateval_t;
typedef const struct rateval *rateval_ct;

struct rate_tuple {
	struct rate_json  obj;
	struct rateval	reset, expires, limit, remaining,
			burst_size, burst_window, results_max,
			offset_max;
};
typedef struct rate_tuple *rate_tuple_t;

/* forwards. */

static const char *dnsdb_setval(const char *, const char *);
static const char *dnsdb_ready(void);
static void dnsdb_destroy(void);
static char *dnsdb_url(const char *, char *, qparam_ct, pdns_fence_ct);
static void dnsdb_info_req(void);
static void dnsdb_info_blob(const char *, size_t);
static void dnsdb_auth(fetch_t);
static const char *dnsdb_status(fetch_t);
static const char *dnsdb_verb_ok(const char *);

static void print_rateval(const char *, rateval_ct, FILE *);
static void print_burstrate(const char *, rateval_ct, rateval_ct, FILE *);
static const char *rateval_make(rateval_t, const json_t *, const char *);
static const char *rate_tuple_make(rate_tuple_t, const char *, size_t);
static void rate_tuple_unmake(rate_tuple_t);

/* variables. */

static const char env_api_key[] = "DNSDB_API_KEY";
static const char env_dnsdb_base_url[] = "DNSDB_SERVER";

static char *api_key = NULL;
static char *dnsdb_base_url = NULL;

static const struct pdns_system dnsdb = {
	"dnsdb", "https://api.dnsdb.info",
	dnsdb_url, dnsdb_info_req, dnsdb_info_blob,
	dnsdb_auth, dnsdb_status, dnsdb_verb_ok,
	dnsdb_setval, dnsdb_ready, dnsdb_destroy
};

/*---------------------------------------------------------------- public
 */

pdns_system_ct
pdns_dnsdb(void) {
	return &dnsdb;
}

/*---------------------------------------------------------------- private
 */

/* dnsdb_setval() -- install configuration element
 */
static const char *
dnsdb_setval(const char *key, const char *value) {
	if (strcmp(key, "apikey") == 0) {
		DESTROY(api_key);
		api_key = strdup(value);
	} else if (strcmp(key, "server") == 0) {
		DESTROY(dnsdb_base_url);
		dnsdb_base_url = strdup(value);
	} else {
		return "dnsdb_setval() unrecognized key";
	}
	return NULL;
}

/* dnsdb_ready() -- override the config file from environment variables?
 */
static const char *
dnsdb_ready(void) {
	const char *value;

	if ((value = getenv(env_api_key)) != NULL) {
		dnsdb_setval("apikey", value);
		DEBUG(1, true, "conf env api_key was set\n");
	}
	if ((value = getenv(env_dnsdb_base_url)) != NULL) {
		dnsdb_setval("server", value);
		DEBUG(1, true, "conf env dnsdb_server = '%s'\n",
		      dnsdb_base_url);
	}
	if (dnsdb_base_url == NULL)
		dnsdb_base_url = strdup(psys->base_url);
	if (api_key == NULL)
		return "no API key given";
	return NULL;
}

/* dnsdb_destroy() -- drop heap storage
 */
static void
dnsdb_destroy(void) {
	DESTROY(api_key);
	DESTROY(dnsdb_base_url);
}

/* dnsdb_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 * returns a string that must be freed.
 */
char *
dnsdb_url(const char *path, char *sep, qparam_ct qpp, pdns_fence_ct fp) {
	const char *verb_path, *p, *scheme_if_needed, *aggr_if_needed;
	char *ret = NULL, *max_count_str = NULL, *offset_str = NULL,
		*first_after_str = NULL, *first_before_str = NULL,
		*last_after_str = NULL, *last_before_str = NULL,
		*query_limit_str = NULL;
	int x;

	/* count the number of slashes in the base url, after the ://
	 * if present.  1 or more means there's a /path after the host.
	 * In that case, don't add /[verb] here, and also don't allow
	 * selecting a verb that's not "lookup" since the /path could
	 * include its own verb. (this is from an old python-era rule.)
	 */
	if ((p = strstr(dnsdb_base_url, "://")) != NULL)
		p += 3;
	else
		p = dnsdb_base_url;
	x = 0;
	for (; *p != '\0'; p++)
		x += (*p == '/');
	verb_path = "";
	if (x == 0) {
		if (pverb->url_fragment != NULL)
			verb_path = pverb->url_fragment;
		else
			verb_path = "/lookup";
	}

	/* supply a scheme if the server string did not. */
	scheme_if_needed = "";
	if (strstr(dnsdb_base_url, "://") == NULL)
		scheme_if_needed = "https://";

	/* handle gravel vs. rocks. */
	aggr_if_needed = "";
	if (qpp->gravel)
		aggr_if_needed = "&aggr=f";

	if (offset > 0) {
		x = asprintf(&offset_str, "&offset=%ld", offset);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (max_count > 0) {
		x = asprintf(&max_count_str, "&max_count=%ld", max_count);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (qpp->query_limit != -1) {
		x = asprintf(&query_limit_str, "&limit=%ld", qpp->query_limit);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (fp->first_after != 0) {
		x = asprintf(&first_after_str, "&time_first_after=%lu",
			     fp->first_after);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->first_before != 0) {
		x = asprintf(&first_before_str, "&time_first_before=%lu",
			     fp->first_before);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->last_after != 0) {
		x = asprintf(&last_after_str, "&time_last_after=%lu",
			     fp->last_after);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->last_before != 0) {
		x = asprintf(&last_before_str, "&time_last_before=%lu",
			     fp->last_before);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	x = asprintf(&ret, "%s%s%s/%s?swclient=%s&version=%s%s%s%s%s%s%s%s%s",
		     scheme_if_needed, dnsdb_base_url, verb_path, path,
		     id_swclient, id_version, aggr_if_needed,
		     or_else(offset_str, ""),
		     or_else(max_count_str, ""),
		     or_else(query_limit_str, ""),
		     or_else(first_after_str, ""),
		     or_else(first_before_str, ""),
		     or_else(last_after_str, ""),
		     or_else(last_before_str, ""));
	if (x < 0) {
		perror("asprintf");
		goto done;
	}

	/* because we append query parameters, tell the caller to use & for
	 * any further query parameters.
	 */
	if (sep != NULL)
		*sep = '&';

 done:
	DESTROY(offset_str);
	DESTROY(max_count_str);
	DESTROY(query_limit_str);
	DESTROY(first_after_str);
	DESTROY(first_before_str);
	DESTROY(last_after_str);
	DESTROY(last_before_str);
	return (ret);
}

static void
dnsdb_info_req(void) {
	query_t query = NULL;
	writer_t writer;

	DEBUG(1, true, "dnsdb_info_req()\n");

	/* start a writer, which might be format functions, or POSIX sort. */
	writer = writer_init(qparam_empty.output_limit);

	/* create a rump query. */
	CREATE(query, sizeof(struct query));
	query->writer = writer;
	query->command = strdup("rate_limit");
	writer->info = true;
	writer->queries = query;

	/* start a status fetch. */
	create_fetch(query, dnsdb_url(query->command, NULL, &qparam_empty,
				      &(struct pdns_fence){}));

	/* run all jobs to completion. */
	io_engine(0);

	/* stop the writer, which might involve reading POSIX sort's output. */
	writer_fini(writer);
}

static void
dnsdb_auth(fetch_t fetch) {
	if (api_key != NULL) {
		char *key_header;

		if (asprintf(&key_header, "X-Api-Key: %s", api_key) < 0)
			my_panic(true, "asprintf");
		fetch->hdrs = curl_slist_append(fetch->hdrs, key_header);
		DESTROY(key_header);
	}
}

static const char *
dnsdb_status(fetch_t fetch) {
	/* early (current) versions of DNSDB returns 404 for "no rrs found". */
	if (fetch->rcode == 404)
		return status_noerror;
	return status_error;
}

static const char *
dnsdb_verb_ok(const char *verb_name) {
	/* -O (offset) cannot be used except for verb "lookup". */
	if (strcasecmp(verb_name, "lookup") != 0 && offset != 0)
		return "only 'lookup' understands offsets";
	return (NULL);
}

/*---------------------------------------------------------------- private
 */

/* print_rateval -- output formatter for rateval.
 */
static void
print_rateval(const char *key, rateval_ct tp, FILE *outf) {
	/* if unspecified, output nothing, not even the key name. */
	if (tp->rk == rk_naught)
		return;

	fprintf(outf, "\t%s: ", key);
	switch (tp->rk) {
	case rk_na:
		fprintf(outf, "n/a");
		break;
	case rk_unlimited:
		fprintf(outf, "unlimited");
		break;
	case rk_int:
		if (strcmp(key, "reset") == 0 || strcmp(key, "expires") == 0)
			fputs(time_str(tp->as_int, iso8601), outf);
		else
			fprintf(outf, "%lu", tp->as_int);
		break;
	case rk_naught: /*FALLTHROUGH*/
	default:
		abort();
	}
	fputc('\n', outf);
}

/* print_burstrate -- output formatter for burst_size, burst_window ratevals.
 */
static void
print_burstrate(const char *key,
		rateval_ct tp_size,
		rateval_ct tp_window,
		FILE *outf)
{
	/* if unspecified, output nothing, not even the key name. */
	if (tp_size->rk == rk_naught || tp_window->rk == rk_naught)
		return;

	assert(tp_size->rk == rk_int);
	assert(tp_window->rk == rk_int);

	u_long b_w = tp_window->as_int;
	u_long b_s = tp_size->as_int;

	fprintf(outf, "\t%s: ", key);

	if (b_w == 3600)
		fprintf(outf, "%lu per hour", b_s);
	else if (b_w == 60)
		fprintf(outf, "%lu per minute", b_s);
	else if ((b_w % 3600) == 0)
		fprintf(outf, "%lu per %lu hours", b_s, b_w / 3600);
	else if ((b_w % 60) == 0)
		fprintf(outf, "%lu per %lu minutes", b_s, b_w / 60);
	else
		fprintf(outf, "%lu per %lu seconds", b_s, b_w);

	fputc('\n', outf);
}

/* dnsdb_write_info -- assumes that fetch contains the complete JSON block.
 */
static void
dnsdb_info_blob(const char *buf, size_t len) {
	if (presentation == pres_text) {
		struct rate_tuple tup;
		const char *msg;

		msg = rate_tuple_make(&tup, buf, len);
		if (msg != NULL) { /* there was an error */
			puts(msg);
		} else {
			puts("rate:");
			print_rateval("reset", &tup.reset, stdout);
			print_rateval("expires", &tup.expires, stdout);
			print_rateval("limit", &tup.limit, stdout);
			print_rateval("remaining", &tup.remaining, stdout);
			print_rateval("results_max", &tup.results_max, stdout);
			print_rateval("offset_max", &tup.offset_max, stdout);
			print_burstrate("burst rate",
					&tup.burst_size, &tup.burst_window,
					stdout);
			rate_tuple_unmake(&tup);
		}
	} else if (presentation == pres_json) {
		fwrite(buf, 1, len, stdout);
	} else {
		abort();
	}
}

/* rateval_make: make an optional key value from the json object.
 *
 * note: a missing key means the corresponding key's value is a "no value".
 */
static const char *
rateval_make(rateval_t tp, const json_t *obj, const char *key) {
	struct rateval rvalue = {rk_naught, 0UL};
	const json_t *jvalue = json_object_get(obj, key);

	if (jvalue != NULL) {
		if (json_is_integer(jvalue)) {
			rvalue.rk = rk_int;
			rvalue.as_int = (u_long)json_integer_value(jvalue);
		} else {
			const char *strvalue = json_string_value(jvalue);
			bool ok = false;

			if (strvalue != NULL) {
				if (strcasecmp(strvalue, "n/a") == 0) {
					rvalue.rk = rk_na;
					ok = true;
				} else if (strcasecmp(strvalue,
						      "unlimited") == 0)
				{
					rvalue.rk = rk_unlimited;
					ok = true;
				}
			}
			if (!ok)
				return ("value must be an integer "
					"or \"n/a\" or \"unlimited\"");
		}
	}
	*tp = rvalue;
	return (NULL);
}

/* rate_tuple_make -- create one rate tuple object out of a JSON object.
 */
static const char *
rate_tuple_make(rate_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;
	json_t *rate;

	memset(tup, 0, sizeof *tup);
	DEBUG(3, true, "[%d] '%-*.*s'\n", (int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%s: warning: json_loadb: %d:%d: %s %s\n",
			program_name, error.line, error.column,
			error.text, error.source);
		abort();
	}
	DEBUG(4, true, "%s\n", json_dumps(tup->obj.main, JSON_INDENT(2)));

	rate = json_object_get(tup->obj.main, "rate");
	if (rate == NULL) {
		msg = "Missing \"rate\" object";
		goto ouch;
	}

	msg = rateval_make(&tup->reset, rate, "reset");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->expires, rate, "expires");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->limit, rate, "limit");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->remaining, rate, "remaining");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->results_max, rate, "results_max");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->offset_max, rate, "offset_max");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->burst_size, rate, "burst_size");
	if (msg != NULL)
		goto ouch;

	msg = rateval_make(&tup->burst_window, rate, "burst_window");
	if (msg != NULL)
		goto ouch;

	assert(msg == NULL);
	return (NULL);

 ouch:
	assert(msg != NULL);
	rate_tuple_unmake(tup);
	return (msg);
}

/* rate_tuple_unmake -- deallocate heap storage associated with a rate tuple.
 */
static void
rate_tuple_unmake(rate_tuple_t tup) {
	json_decref(tup->obj.main);
}

#endif /*WANT_PDNS_DNSDB*/
