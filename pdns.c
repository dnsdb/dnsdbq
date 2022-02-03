/*
 * Copyright (c) 2014-2021 by Farsight Security, Inc.
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

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include "asinfo.h"
#include "defs.h"
#include "netio.h"
#include "ns_ttl.h"
#include "pdns.h"
#include "time.h"
#include "tokstr.h"
#include "globals.h"

static void present_text_line(const char *, const char *, const char *);
static void present_csv_line(pdns_tuple_ct, const char *);
static void present_minimal_thing(const char *thing);
static json_t *annotate_json(pdns_tuple_ct, bool);
static json_t *annotate_one(json_t *, const char *, const char *, json_t *);
#ifndef CRIPPLED_LIBC
static json_t *annotate_asinfo(const char *, const char *);
#endif
static struct counted *countoff_r(const char *, int);

/* present_text_lookup -- render one pdns tuple in "dig" style ascii text.
 */
void
present_text_lookup(pdns_tuple_ct tup,
		    mode_e mode __attribute__ ((unused)),
		    writer_t writer __attribute__ ((unused)))
{
	bool pflag, ppflag;
	const char *prefix;

	ppflag = false;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		char duration[50];

		if (ns_format_ttl(tup->time_last - tup->time_first + 1, //non-0
				  duration, sizeof duration) < 0)
			strcpy(duration, "?");
		printf(";; record times: %s",
			time_str(tup->time_first, iso8601));
		printf(" .. %s (%s)\n",
			time_str(tup->time_last, iso8601),
			duration);
		ppflag = true;
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		char duration[50];

		if (ns_format_ttl(tup->zone_last - tup->zone_first, // no +1
				  duration, sizeof duration) < 0)
			strcpy(duration, "?");
		printf(";;   zone times: %s",
			time_str(tup->zone_first, iso8601));
		printf(" .. %s (%s)\n",
			time_str(tup->zone_last, iso8601),
			duration);
		ppflag = true;
	}

	/* Count and Bailiwick. */
	prefix = ";;";
	pflag = false;
	if (tup->obj.count != NULL) {
		printf("%s count: %lld", prefix, (long long)tup->count);
		prefix = ";";
		pflag = true;
		ppflag = true;
	}
	if (tup->obj.bailiwick != NULL) {
		printf("%s bailiwick: %s", prefix, tup->bailiwick);
		prefix = NULL;
		pflag = true;
		ppflag = true;
	}
	if (pflag)
		putchar('\n');

	/* Records. */
	if (json_is_array(tup->obj.rdata)) {
		size_t index;
		json_t *rr;

		json_array_foreach(tup->obj.rdata, index, rr) {
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			present_text_line(tup->rrname, tup->rrtype, rdata);
			ppflag = true;
		}
	} else {
		present_text_line(tup->rrname, tup->rrtype, tup->rdata);
		ppflag = true;
	}

	/* Cleanup. */
	if (ppflag)
		putchar('\n');
}

/* present_text_line -- render one RR in "dig" style ascii text.
 */
static void
present_text_line(const char *rrname, const char *rrtype, const char *rdata) {
	char *asnum = NULL, *cidr = NULL, *comment = NULL, *result = NULL;

#ifndef CRIPPLED_LIBC
	result = asinfo_from_rr(rrtype, rdata, &asnum, &cidr);
#endif
	if (result != NULL) {
		comment = result;
		result = NULL;
	} else if (asnum != NULL && cidr != NULL) {
		const char *src = asnum;
		bool wordbreak = true;
		char ch, *dst;

		dst = comment = malloc(strlen(asnum) * 3 + strlen(cidr) + 1);
		while ((ch = *src++) != '\0') {
			if (wordbreak) {
				*dst++ = 'A';
				*dst++ = 'S';
			}
			*dst++ = ch;
			wordbreak = (ch == '\040');
		}
		*dst++ = '\040';
		dst = stpcpy(dst, cidr);
		free(asnum);
		free(cidr);
	}
	printf("%s  %s  %s", rrname, rrtype, rdata);
	if (comment != NULL) {
		printf("  ; %s", comment);
		free(comment);
	}
	putchar('\n');
}

/* present_text_summ -- render summarize object in "dig" style ascii text.
 */
void
present_text_summarize(pdns_tuple_ct tup,
		       mode_e mode __attribute__ ((unused)),
		       writer_t writer __attribute__ ((unused)))
{
	const char *prefix;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		printf(";; record times: %s",
		       time_str(tup->time_first, iso8601));
		printf(" .. %s\n",
		       time_str(tup->time_last, iso8601));
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		printf(";;   zone times: %s",
		       time_str(tup->zone_first, iso8601));
		printf(" .. %s\n",
		       time_str(tup->zone_last, iso8601));
		putchar('\n');
	}

	/* Count and Num_Results. */
	prefix = ";;";
	if (tup->obj.count != NULL) {
		printf("%s count: %lld",
		       prefix, (long long)tup->count);
		prefix = ";";
	}
	if (tup->obj.num_results != NULL) {
		printf("%s num_results: %lld",
		       prefix, (long long)tup->num_results);
		prefix = NULL;
	}

	putchar('\n');
}

/* pprint_json -- pretty-print a JSON buffer after validation.
 *
 * returns true if could parse the json ok, otherwise returns false.
 */
bool
pprint_json(const char *buf, size_t len, FILE *outf) {
	json_error_t error;

	json_t *js = json_loadb(buf, len, 0, &error);
	if (js == NULL) {
		fprintf(stderr, "JSON parsing error %d:%d: %s %s\n",
			error.line, error.column,
			error.text, error.source);
		return false;
	}

	json_dumpf(js, outf, JSON_INDENT(2));
	fputc('\n', outf);

	json_decref(js);
	return true;
}

/* present_json_lookup -- render one DNSDB tuple as newline-separated JSON.
 */
void
present_json_lookup(pdns_tuple_ct tup,
		    mode_e mode __attribute__ ((unused)),
		    writer_t writer __attribute__ ((unused)))
{
	present_json(tup, true);
}

/* present_json_summarize -- render one DNSDB tuple as newline-separated JSON.
 */
void
present_json_summarize(pdns_tuple_ct tup,
		       mode_e mode __attribute__ ((unused)),
		       writer_t writer __attribute__ ((unused)))
{
	present_json(tup, false);
}

/* present_json -- shared renderer for DNSDB JSON tuples (lookup and summarize)
 */
void
present_json(pdns_tuple_ct tup, bool rd) {
	json_t *copy = annotate_json(tup, rd);

	if (copy != NULL) {
		json_dumpf(copy, stdout, JSON_INDENT(0) | JSON_COMPACT);
		json_decref(copy);
	} else {
		json_dumpf(tup->obj.cof_obj, stdout,
			   JSON_INDENT(0) | JSON_COMPACT);
	}
	putchar('\n');
}

/* annotate_json -- create a temporary copy of a tuple; apply transforms.
 */
static json_t *
annotate_json(pdns_tuple_ct tup, bool rd) {
	json_t *annoRD = NULL, *annoTF = NULL, *annoTL = NULL,
		*annoZF = NULL, *annoZL = NULL;

	/* annotate zone first/last? */
	if ((transforms & TRANS_DATEFIX) != 0 &&
	    tup->obj.zone_first != NULL && tup->obj.zone_last != NULL)
	{
		annoZF = json_string_nocheck(time_str(tup->zone_first,
						      iso8601));
		annoZL = json_string_nocheck(time_str(tup->zone_last,
						      iso8601));
	}

	/* annotate time first/last? */
	if ((transforms & TRANS_DATEFIX) != 0 &&
	    tup->obj.time_first != NULL && tup->obj.time_last != NULL)
	{
		annoTF = json_string_nocheck(time_str(tup->time_first,
						      iso8601));
		annoTL = json_string_nocheck(time_str(tup->time_last,
						      iso8601));
	}

	/* annotate rdata? */
	if (rd) {
		if (json_is_array(tup->obj.rdata)) {
			size_t index;
			json_t *rr;

			json_array_foreach(tup->obj.rdata, index, rr) {
				const char *rdata = json_string_value(rr);
				json_t *asinfo = NULL;
#ifndef CRIPPLED_LIBC
				asinfo = annotate_asinfo(tup->rrtype, rdata);
#endif
				if (asinfo != NULL)
					annoRD = annotate_one(annoRD, rdata,
							      "asinfo", asinfo);
			}
		} else {
			json_t *asinfo = NULL;
#ifndef CRIPPLED_LIBC
			asinfo = annotate_asinfo(tup->rrtype, tup->rdata);
#endif
			if (asinfo != NULL)
				annoRD = annotate_one(annoRD, tup->rdata,
						      "asinfo", asinfo);
		}
	} //rd?

	/* anything annotated? */
	if ((annoZF != NULL && annoZL != NULL) ||
	    (annoTF != NULL && annoTL != NULL) ||
	    (transforms & (TRANS_REVERSE|TRANS_CHOMP)) != 0 ||
	    annoRD != NULL)
	{
		json_t *copy = json_deep_copy(tup->obj.cof_obj);

		if (annoZF != NULL || annoZL != NULL) {
			json_object_set_new_nocheck(copy, "zone_time_first",
						    annoZF);
			json_object_set_new_nocheck(copy, "zone_time_last",
						    annoZL);
		}
		if (annoTF != NULL || annoTL != NULL) {
			json_object_set_new_nocheck(copy, "time_first",
						    annoTF);
			json_object_set_new_nocheck(copy, "time_last",
						    annoTL);
		}
		if ((transforms & (TRANS_REVERSE|TRANS_CHOMP)) != 0)
			json_object_set_new_nocheck(copy, "rrname",
						    json_string(tup->rrname));
		if (annoRD != NULL)
			json_object_set_new_nocheck(copy, "dnsdbq_rdata",
						    annoRD);
		return copy;
	}
	return NULL;
}

static json_t *
annotate_one(json_t *anno, const char *rdata, const char *name, json_t *obj) {
	json_t *this = NULL;
	bool new = false;

	if (anno == NULL)
		anno = json_object();
	if ((this = json_object_get(anno, rdata)) == NULL) {
		this = json_object();
		new = true;
	}
	json_object_set_new_nocheck(this, name, obj);
	if (new)
		json_object_set_new_nocheck(anno, rdata, this);
	else
		json_decref(this);
	return anno;
}

#ifndef CRIPPLED_LIBC
static json_t *
annotate_asinfo(const char *rrtype, const char *rdata) {
	char *asnum = NULL, *cidr = NULL, *result = NULL;
	json_t *asinfo = NULL;

	if ((result = asinfo_from_rr(rrtype, rdata, &asnum, &cidr)) != NULL) {
		asinfo = json_object();
		json_object_set_new_nocheck(asinfo, "comment",
					    json_string(result));
		free(result);
	} else if (asnum != NULL && cidr != NULL) {
		json_t *array = json_array();
		struct tokstr *ts = tokstr_string(asnum);
		for (char *t; (t = tokstr_next(ts, "\040")) != NULL; free(t))
			json_array_append_new(array, json_integer(atol(t)));
		tokstr_last(&ts);
		asinfo = json_object();
		json_object_set_new_nocheck(asinfo, "as", array);
		json_object_set_new_nocheck(asinfo, "cidr", json_string(cidr));
	}
	DESTROY(asnum);
	DESTROY(cidr);
	return asinfo;
}
#endif

/* present_csv_lookup -- render one DNSDB tuple as comma-separated values (CSV)
 */
void
present_csv_lookup(pdns_tuple_ct tup,
		   mode_e mode __attribute__ ((unused)),
		   writer_t writer)
{
	if (!writer->csv_headerp) {
		printf("time_first,time_last,zone_first,zone_last,"
		       "count,bailiwick,"
		       "rrname,rrtype,rdata");
		if (asinfo_lookup)
			fputs(",asnum,cidr", stdout);
		putchar('\n');
		writer->csv_headerp = true;
	}

	if (json_is_array(tup->obj.rdata)) {
		size_t index;
		json_t *rr;

		json_array_foreach(tup->obj.rdata, index, rr) {
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			present_csv_line(tup, rdata);
		}
	} else {
		present_csv_line(tup, tup->rdata);
	}
}

/* present_csv_line -- display a CSV for one rdatum out of an rrset.
 */
static void
present_csv_line(pdns_tuple_ct tup, const char *rdata) {
	/* Timestamps. */
	if (tup->obj.time_first != NULL)
		printf("\"%s\"", time_str(tup->time_first, iso8601));
	putchar(',');
	if (tup->obj.time_last != NULL)
		printf("\"%s\"", time_str(tup->time_last, iso8601));
	putchar(',');
	if (tup->obj.zone_first != NULL)
		printf("\"%s\"", time_str(tup->zone_first, iso8601));
	putchar(',');
	if (tup->obj.zone_last != NULL)
		printf("\"%s\"", time_str(tup->zone_last, iso8601));
	putchar(',');

	/* Count and bailiwick. */
	if (tup->obj.count != NULL)
		printf("%lld", (long long) tup->count);
	putchar(',');
	if (tup->obj.bailiwick != NULL)
		printf("\"%s\"", tup->bailiwick);
	putchar(',');

	/* Records. */
	if (tup->obj.rrname != NULL)
		printf("\"%s\"", tup->rrname);
	putchar(',');
	if (tup->obj.rrtype != NULL)
		printf("\"%s\"", tup->rrtype);
	putchar(',');
	if (tup->obj.rdata != NULL)
		printf("\"%s\"", rdata);
	if (asinfo_lookup && tup->obj.rrtype != NULL &&
	    tup->obj.rdata != NULL) {
		char *asnum = NULL, *cidr = NULL, *result = NULL;

#ifndef CRIPPLED_LIBC
		result = asinfo_from_rr(tup->rrtype, rdata, &asnum, &cidr);
#endif
		if (result != NULL) {
			asnum = strdup(result);
			cidr = result;
			result = NULL;
		}
		putchar(',');
		if (asnum != NULL) {
			printf("\"%s\"", asnum);
			free(asnum);
		}
		putchar(',');
		if (cidr != NULL) {
			printf("\"%s\"", cidr);
			free(cidr);
		}
	}
	putchar('\n');
}

/* present_rdata_lookup -- render one DNSDB tuple as a "line" (MINIMAL)
 */
void
present_minimal_lookup(pdns_tuple_ct tup,
		       mode_e mode __attribute__ ((unused)),
		       writer_t writer __attribute__ ((unused)))
{
	/* did this tuple come from a left hand or right hand query? */
	bool left = true;
	switch (mode) {
	case no_mode:
		abort();
	case rrset_mode:
		/* FALLTHROUGH */
	case raw_rrset_mode:
		break;
	case name_mode:
		/* FALLTHROUGH */
	case ip_mode:
		/* FALLTHROUGH */
	case raw_name_mode:
		left = false;
	}

	/* for RHS queries, output the LHS once, and exit. */
	if (!left) {
		present_minimal_thing(tup->rrname);
		return;
	}

	/* for LHS queries, output each RHS found. */
	if (json_is_array(tup->obj.rdata)) {
		size_t index;
		json_t *rr;

		json_array_foreach(tup->obj.rdata, index, rr) {
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			present_minimal_thing(rdata);
		}
	} else {
		present_minimal_thing(tup->rdata);
	}
}

static void
present_minimal_thing(const char *thing) {
	if (!deduper_tas(minimal_deduper, thing))
		puts(thing);
}

/* present_csv_summ -- render a summarize result as CSV.
 */
void
present_csv_summarize(pdns_tuple_ct tup,
		      mode_e mode __attribute__ ((unused)),
		      writer_t writer __attribute__ ((unused)))
{
	printf("time_first,time_last,zone_first,zone_last,"
	       "count,num_results\n");

	/* Timestamps. */
	if (tup->obj.time_first != NULL)
		printf("\"%s\"", time_str(tup->time_first, iso8601));
	putchar(',');
	if (tup->obj.time_last != NULL)
		printf("\"%s\"", time_str(tup->time_last, iso8601));
	putchar(',');
	if (tup->obj.zone_first != NULL)
		printf("\"%s\"", time_str(tup->zone_first, iso8601));
	putchar(',');
	if (tup->obj.zone_last != NULL)
		printf("\"%s\"", time_str(tup->zone_last, iso8601));
	putchar(',');

	/* Count and num_results. */
	if (tup->obj.count != NULL)
		printf("%lld", (long long) tup->count);
	putchar(',');
	if (tup->obj.num_results != NULL)
		printf("%lld", tup->num_results);
	putchar('\n');
}

/* tuple_make -- create one DNSDB tuple object out of a JSON object.
 */
const char *
tuple_make(pdns_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

	memset(tup, 0, sizeof *tup);
	DEBUG(4, true, "[%d] '%-*.*s'\n", (int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%s: warning: json_loadb: %d:%d: %s %s\n",
			program_name, error.line, error.column,
			error.text, error.source);
		abort();
	}
	if (debug_level >= 4) {
		char *pretty = json_dumps(tup->obj.main, JSON_INDENT(2));
		fprintf(stderr, "debug: %s\n", pretty);
		free(pretty);
	}

	switch (psys->encap) {
	case encap_cof:
		/* the COF just is the JSON object. */
		tup->obj.cof_obj = tup->obj.main;
		break;
	case encap_saf:
		/* the COF is embedded in the JSONL object. */
		tup->obj.saf_cond = json_object_get(tup->obj.main, "cond");
		if (tup->obj.saf_cond != NULL) {
			if (!json_is_string(tup->obj.saf_cond)) {
				msg = "cond must be a string";
				goto ouch;
			}
			tup->cond = json_string_value(tup->obj.saf_cond);
		}

		tup->obj.saf_msg = json_object_get(tup->obj.main, "msg");
		if (tup->obj.saf_msg != NULL) {
			if (!json_is_string(tup->obj.saf_msg)) {
				msg = "msg must be a string";
				goto ouch;
			}
			tup->msg = json_string_value(tup->obj.saf_msg);
		}

		tup->obj.saf_obj = json_object_get(tup->obj.main, "obj");
		if (tup->obj.saf_obj != NULL) {
			if (!json_is_object(tup->obj.saf_obj)) {
				msg = "obj must be an object";
				goto ouch;
			}
			tup->obj.cof_obj = tup->obj.saf_obj;
		}
		break;
	default:
		/* we weren't prepared for this -- unknown program state. */
		abort();
	}

	/* Timestamps. */
	tup->obj.zone_first = json_object_get(tup->obj.cof_obj,
					      "zone_time_first");
	if (tup->obj.zone_first != NULL) {
		if (!json_is_integer(tup->obj.zone_first)) {
			msg = "zone_time_first must be an integer";
			goto ouch;
		}
		tup->zone_first = (u_long)
			json_integer_value(tup->obj.zone_first);
	}
	tup->obj.zone_last =
		json_object_get(tup->obj.cof_obj, "zone_time_last");
	if (tup->obj.zone_last != NULL) {
		if (!json_is_integer(tup->obj.zone_last)) {
			msg = "zone_time_last must be an integer";
			goto ouch;
		}
		tup->zone_last = (u_long)
			json_integer_value(tup->obj.zone_last);
	}
	tup->obj.time_first = json_object_get(tup->obj.cof_obj, "time_first");
	if (tup->obj.time_first != NULL) {
		if (!json_is_integer(tup->obj.time_first)) {
			msg = "time_first must be an integer";
			goto ouch;
		}
		tup->time_first = (u_long)
			json_integer_value(tup->obj.time_first);
	}
	tup->obj.time_last = json_object_get(tup->obj.cof_obj, "time_last");
	if (tup->obj.time_last != NULL) {
		if (!json_is_integer(tup->obj.time_last)) {
			msg = "time_last must be an integer";
			goto ouch;
		}
		tup->time_last = (u_long)
			json_integer_value(tup->obj.time_last);
	}

	/* Count. */
	tup->obj.count = json_object_get(tup->obj.cof_obj, "count");
	if (tup->obj.count != NULL) {
		if (!json_is_integer(tup->obj.count)) {
			msg = "count must be an integer";
			goto ouch;
		}
		tup->count = json_integer_value(tup->obj.count);
	}
	/* Bailiwick. */
	tup->obj.bailiwick = json_object_get(tup->obj.cof_obj, "bailiwick");
	if (tup->obj.bailiwick != NULL) {
		if (!json_is_string(tup->obj.bailiwick)) {
			msg = "bailiwick must be a string";
			goto ouch;
		}
		tup->bailiwick = json_string_value(tup->obj.bailiwick);
	}
	/* num_results -- just for a summarize. */
	tup->obj.num_results =
		json_object_get(tup->obj.cof_obj, "num_results");
	if (tup->obj.num_results != NULL) {
		if (!json_is_integer(tup->obj.num_results)) {
			msg = "num_results must be an integer";
			goto ouch;
		}
		tup->num_results = json_integer_value(tup->obj.num_results);
	}

	/* Records. */
	tup->obj.rrname = json_object_get(tup->obj.cof_obj, "rrname");
	if (tup->obj.rrname != NULL) {
		if (!json_is_string(tup->obj.rrname)) {
			msg = "rrname must be a string";
			goto ouch;
		}

		char *r = strdup(json_string_value(tup->obj.rrname));
		int dot = 0;

		if ((transforms & TRANS_REVERSE) != 0) {
			char *t = reverse(r);
			DESTROY(r);
			r = t;
			t = NULL;
			/* leading dot comes from reverse() */
			if ((transforms & TRANS_CHOMP) != 0)
				dot = 1;
		} else if ((transforms & TRANS_CHOMP) != 0) {
			/* unescaped trailing dot? */
			size_t l = strlen(r);
			if (l > 0 && r[l-1] == '.' &&
			    (l == 1 || r[l-2] != '\\'))
				r[l-1] = '\0';
		}

		if (dot) {
			/* in chomp+reverse, the dot to chomp is now leading. */
			tup->rrname = strdup(r + dot);
			DESTROY(r);
		} else {
			tup->rrname = r;
		}
	}
	tup->obj.rrtype = json_object_get(tup->obj.cof_obj, "rrtype");
	if (tup->obj.rrtype != NULL) {
		if (!json_is_string(tup->obj.rrtype)) {
			msg = "rrtype must be a string";
			goto ouch;
		}
		tup->rrtype = json_string_value(tup->obj.rrtype);
	}
	tup->obj.rdata = json_object_get(tup->obj.cof_obj, "rdata");
	if (tup->obj.rdata != NULL) {
		if (json_is_string(tup->obj.rdata)) {
			tup->rdata = json_string_value(tup->obj.rdata);
		} else if (!json_is_array(tup->obj.rdata)) {
			msg = "rdata must be a string or array";
			goto ouch;
		}
		/* N.b., the array case is for the consumer to iterate over. */
	}

	assert(msg == NULL);
	return NULL;

 ouch:
	assert(msg != NULL);
	tuple_unmake(tup);
	return msg;
}

/* tuple_unmake -- deallocate the heap storage associated with one tuple.
 */
void
tuple_unmake(pdns_tuple_t tup) {
	DESTROY(tup->rrname);
	json_decref(tup->obj.main);
}

/* countoff{_r,_debug} -- count and map the labels in a DNS name.
 */
static struct counted *
countoff_r(const char *src, int nlabel) {
	const char *sp = src;
	bool slash = false;
	struct counted *c;
	int ch;

	/* count and map the alnums in the facing dns label. */
	size_t nalnum = 0;
	while ((ch = *sp++) != '\0') {
		if (isalnum(ch))
			nalnum++;
		if (!slash) {
			if (ch == '\\')
				slash = true;
			else if (ch == '.')
				break;
		} else {
			slash = false;
		}
	}
	size_t len = (size_t) (sp - src);
	if (ch == '.') {
		/* end of label, recurse to reach rest of name. */
		c = countoff_r(sp, nlabel+1);
		/* fill in output structure on the way back up. */
		c->nchar += len;
		c->nalnum += nalnum;
		c->lens[nlabel] = len;
	} else if (ch == '\0') {
		/* end of name, and perhaps of a unterminated label. */
		len--; /*'\0'*/
		if (len != 0)
			nlabel++;
		c = (struct counted *)malloc(COUNTED_SIZE(nlabel));
		memset(c, 0, COUNTED_SIZE(nlabel));
		c->nlabel = nlabel;
		c->nalnum = nalnum;
		if (len != 0) {
			c->nchar = len;
			c->lens[nlabel-1] = c->nchar;
		}
	} else {
		abort();
	}
	return c;
}

struct counted *
countoff(const char *src) {
	return countoff_r(src, 0);
}

void
countoff_debug(const char *place, const char *thing, const struct counted *c) {
	printf("\"%s\" -> {nlabel %d, nchar %zd, nalnum %zd, lens [",
	       thing, c->nlabel, c->nchar, c->nalnum);
	const char *sep = "";
	for (int i = 0; i < c->nlabel; i++) {
		printf("%s%zd", sep, c->lens[i]);
		sep = ", ";
	}
	printf("]} (%s)\n", place);
}

/* reverse -- put a domain name into TLD-first order.
 *
 * returns NULL if errno is set, else, a heap string.
 */
char *
reverse(const char *src) {
	struct counted *c = countoff(src);
	char *ret = malloc(c->nchar + 1/*'.'*/ + 1/*'\0'*/);
	char *p = ret;
	size_t nchar = 0;

	for (ssize_t i = (ssize_t)c->nlabel-1; i >= 0; i--) {
		size_t dot = (src[c->nchar - nchar - 1] == '.');
		*p++ = '.';
		memcpy(p, src + c->nchar - nchar - c->lens[i],
		       c->lens[i] - dot);
		p += c->lens[i] - dot;
		nchar += c->lens[i];
	}
	*p = '\0';
	DESTROY(c);
	return ret;
}

/* data_blob -- process one deblocked json blob as a counted string.
 *
 * presents, or outputs to POSIX sort(1), each blob and then frees it.
 * returns number of tuples processed (for now, 1 or 0).
 */
int
data_blob(fetch_t fetch, size_t len) {
	query_t query = fetch->query;
	writer_t writer = query->writer;
	struct pdns_tuple tup;
	u_long first, last;
	const char *msg;
	int ret = 0;

	msg = tuple_make(&tup, fetch->buf, len);
	if (msg != NULL) {
		fputs(msg, stderr);
		fputc('\n', stderr);
		goto more;
	}

	if (psys->encap == encap_saf) {
		if (tup.msg != NULL) {
			DEBUG(5, true, "data_blob tup.msg = %s\n", tup.msg);
			fetch->saf_msg = strdup(tup.msg);
		}

		if (tup.cond != NULL) {
			DEBUG(5, true, "data_blob tup.cond = %s\n", tup.cond);
			/* if we goto next now, this line will not be counted.
			 */
			if (strcmp(tup.cond, "begin") == 0) {
				fetch->saf_cond = sc_begin;
				goto next;
			} else if (strcmp(tup.cond, "ongoing") == 0) {
				/* "cond":"ongoing" key vals should
				 * be ignored but the rest of line used. */
				fetch->saf_cond = sc_ongoing;
			} else if (strcmp(tup.cond, "succeeded") == 0) {
				fetch->saf_cond = sc_succeeded;
				goto next;
			} else if (strcmp(tup.cond, "limited") == 0) {
				fetch->saf_cond = sc_limited;
				goto next;
			} else if (strcmp(tup.cond, "failed") == 0) {
				fetch->saf_cond = sc_failed;
				goto next;
			} else {
				/* use sc_missing for an invalid cond value */
				fetch->saf_cond = sc_missing;
				fprintf(stderr,
					"%s: Unknown value for \"cond\": %s\n",
					program_name, tup.cond);
			}
		}

		/* A COF keepalive will have no "obj"
		 * but may have a "cond" or "msg".
		 */
		if (tup.obj.saf_obj == NULL) {
			DEBUG(4, true,
			      "COF object is empty, i.e. a keepalive\n");
			goto next;
		}
	}

	/* there are two sets of timestamps in a tuple. we prefer
	 * the on-the-wire times to the zone times, when available.
	 */
	if (tup.time_first != 0 && tup.time_last != 0) {
		first = (u_long)tup.time_first;
		last = (u_long)tup.time_last;
	} else {
		first = (u_long)tup.zone_first;
		last = (u_long)tup.zone_last;
	}

	if (sorting != no_sort) {
		/* POSIX sort(1) is given six extra fields at the front
		 * of each line (first,last,duration,count,name,data)
		 * which are accessed as -k1 .. -k7 on the
		 * sort command line. we strip them off later
		 * when reading the result back. the reason
		 * for all this PDP11-era logic is to avoid
		 * having to store the full result in memory.
		 */
		char *dyn_rrname = sortable_rrname(&tup),
			*dyn_rdata = sortable_rdata(&tup);

		DEBUG(3, true, "dyn_rrname = '%s'\n", dyn_rrname);
		DEBUG(3, true, "dyn_rdata = '%s'\n", dyn_rdata);
		fprintf(writer->sort_stdin,
			"%lu %lu %lu %lu %s %s %s %d %*.*s\n",
			(unsigned long)first,
			(unsigned long)last,
			(unsigned long)(last - first),
			(unsigned long)tup.count,
			or_else(dyn_rrname, "n/a"),
			tup.rrtype,
			or_else(dyn_rdata, "n/a"),
			(int)query->mode,
			(int)len, (int)len, fetch->buf);
		DEBUG(2, true, "sort0: '%lu %lu %lu %lu %s %s %s %d %*.*s'\n",
		      (unsigned long)first,
		      (unsigned long)last,
		      (unsigned long)(last - first),
		      (unsigned long)tup.count,
		      or_else(dyn_rrname, "n/a"),
		      tup.rrtype,
		      or_else(dyn_rdata, "n/a"),
		      (int)query->mode,
		      (int)len, (int)len, fetch->buf);
		DESTROY(dyn_rrname);
		DESTROY(dyn_rdata);
	} else {
		(*presenter)(&tup, query->mode, writer);
	}

	ret = 1;
 next:
	tuple_unmake(&tup);
 more:
	return ret;
}

/* pick_system -- find a named system descriptor, return t/f as to "found?"
 *
 * returns if psys != NULL, or exits fatally otherwise.
 */
void
pick_system(const char *name, const char *context) {
	pdns_system_ct tsys = NULL;
	char *msg = NULL;

	DEBUG(1, true, "pick_system(%s)\n", name);
#if WANT_PDNS_DNSDB
	if (strcmp(name, "dnsdb1") == 0)
		tsys = pdns_dnsdb1();
	/* "dnsdb" is an alias for "dnsdb2". */
	if (strcmp(name, "dnsdb2") == 0 || strcmp(name, "dnsdb") == 0)
		tsys = pdns_dnsdb2();
#endif
#if WANT_PDNS_CIRCL
	if (strcmp(name, "circl") == 0)
		tsys = pdns_circl();
#endif
	if (tsys == NULL) {
		if (asprintf(&msg,
			     "unrecognized system name (%s)", name) < 0)
			my_panic(true, "asprintf");
	} else if (tsys == psys) {
		/* likely recursion via read_config due to DNSDBQ_SYSTEM. */
		return;
	} else {
		if (psys != NULL) {
			psys->destroy();
			psys = NULL;
		}
		psys = tsys;
		tsys = NULL;
		if (config_file != NULL)
			read_config();
		const char *tmsg = psys->ready();
		if (tmsg != NULL) {
			msg = strdup(tmsg);
			tmsg = NULL;
		}
	}

	if (msg != NULL) {
		fprintf(stderr, "%s (in %s)\n", msg, context);
		DESTROY(msg);
		my_exit(1);
	}
}

/* read_config -- parse a given config file.
 */
void
read_config(void) {
	char *cmd, *line;
	size_t n;
	int x, l;
	FILE *f;

	/* in the "echo dnsdb server..." lines, the
	 * first parameter is the pdns system to which to dispatch
	 * the key and value (i.e. second the third parameters).
	 */
	x = asprintf(&cmd,
		     "set -e; . '%s';"
		     "echo dnsdbq system ${" DNSDBQ_SYSTEM
			":-" DEFAULT_SYS "};"
#if WANT_PDNS_DNSDB
		     "echo dnsdb1 apikey ${DNSDB_API_KEY:-$APIKEY};"
		     "echo dnsdb1 server $DNSDB_SERVER;"
		     "echo dnsdb2 apikey ${DNSDB_API_KEY:-$APIKEY};"
		     "echo dnsdb2 server $DNSDB_SERVER;"
#endif
#if WANT_PDNS_CIRCL
		     "echo circl apikey $CIRCL_AUTH;"
		     "echo circl server $CIRCL_SERVER;"
#endif
		     "exit", config_file);
	if (x < 0)
		my_panic(true, "asprintf");
	// this variable can be set in the config file but not the environ.
	unsetenv("APIKEY");
	f = popen(cmd, "r");
	if (f == NULL) {
		fprintf(stderr, "%s: [%s]: %s",
			program_name, cmd, strerror(errno));
		DESTROY(cmd);
		my_exit(1);
	}
	DEBUG(1, true, "conf cmd = '%s'\n", cmd);
	DESTROY(cmd);
	line = NULL;
	n = 0;
	l = 0;
	while (getline(&line, &n, f) > 0) {
		char *tok1, *tok2, *tok3;
		char *saveptr = NULL;
		const char *msg;

		l++;
		if (strchr(line, '\n') == NULL) {
			fprintf(stderr, "%s: conf line #%d: too long\n",
				program_name, l);
			my_exit(1);
		}
		tok1 = strtok_r(line, "\040\012", &saveptr);
		tok2 = strtok_r(NULL, "\040\012", &saveptr);
		tok3 = strtok_r(NULL, "\040\012", &saveptr);
		if (tok1 == NULL || tok2 == NULL) {
			fprintf(stderr,
				"%s: conf line #%d: malformed\n",
				program_name, l);
			my_exit(1);
		}
		if (tok3 == NULL || *tok3 == '\0') {
			/* variable wasn't set, ignore the line. */
			continue;
		}

		/* some env/conf variables are dnsdbq-specific. */
		if (strcmp(tok1, "dnsdbq") == 0) {
			/* env/config psys does not override -u. */
			if (strcmp(tok2, "system") == 0 && !psys_specified) {
				pick_system(tok3, config_file);
				if (psys == NULL) {
					fprintf(stderr, "%s: unknown %s %s\n",
						program_name,
						DNSDBQ_SYSTEM,
						tok3);
					my_exit(1);
				}
			}
			continue;
		}

		/* if this variable is for this system, consume it. */
		if (debug_level >= 1) {
			char *t = NULL;

			if (strcmp(tok2, "apikey") == 0) {
				int ignored __attribute__((unused));
				ignored = asprintf(&t, "[%zu]", strlen(tok3));
			} else
				t = strdup(tok3);
			fprintf(stderr, "line #%d: sets %s|%s|%s\n",
				l, tok1, tok2, t);
			DESTROY(t);
		}
		if (strcmp(tok1, psys->name) == 0) {
			msg = psys->setval(tok2, tok3);
			if (msg != NULL) {
				fprintf(stderr, "setval: %s\n", msg);
				my_exit(1);
			}
		}
	}
	DESTROY(line);
	x = pclose(f);
	if (!WIFEXITED(x) || WEXITSTATUS(x) != 0)
		my_exit(1);
	assert(psys != NULL);
}
