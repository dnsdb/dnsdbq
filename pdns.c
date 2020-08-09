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

#include <assert.h>

#include "defs.h"
#include "netio.h"
#include "ns_ttl.h"
#include "pdns.h"
#include "time.h"
#include "globals.h"

static void present_csv_line(pdns_tuple_ct, const char *);

/* present_text_look -- render one pdns tuple in "dig" style ascii text.
 */
void
present_text_lookup(pdns_tuple_ct tup,
		    const char *jsonbuf __attribute__ ((unused)),
		    size_t jsonlen __attribute__ ((unused)),
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
		size_t slot, nslots;

		nslots = json_array_size(tup->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(tup->obj.rdata, slot);
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			printf("%s  %s  %s\n",
				tup->rrname, tup->rrtype, rdata);
			ppflag = true;
		}
	} else {
		printf("%s  %s  %s\n",
			tup->rrname, tup->rrtype, tup->rdata);
		ppflag = true;
	}

	/* Cleanup. */
	if (ppflag)
		putchar('\n');
}

/* present_text_summ -- render summarize object in "dig" style ascii text.
 */
void
present_text_summarize(pdns_tuple_ct tup,
		       const char *jsonbuf __attribute__ ((unused)),
		       size_t jsonlen __attribute__ ((unused)),
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
	json_t	*js;
	json_error_t error;

	js = json_loadb(buf, len, 0, &error);
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

/* present_json -- render one DNSDB tuple as newline-separated JSON.
 *
 * note: used by both lookup and summarize verbs.
 */
void
present_json(pdns_tuple_ct tup,
	     const char *jsonbuf __attribute__ ((unused)),
	     size_t jsonlen __attribute__ ((unused)),
	     writer_t writer __attribute__ ((unused)))
{
	json_dumpf(tup->obj.cof_obj, stdout, JSON_INDENT(0) | JSON_COMPACT);
	putchar('\n');
}

/* present_csv_look -- render one DNSDB tuple as comma-separated values (CSV).
 */
void
present_csv_lookup(pdns_tuple_ct tup,
		   const char *jsonbuf __attribute__ ((unused)),
		   size_t jsonlen __attribute__ ((unused)),
		   writer_t writer)
{
	if (!writer->csv_headerp) {
		printf("time_first,time_last,zone_first,zone_last,"
		       "count,bailiwick,"
		       "rrname,rrtype,rdata\n");
		writer->csv_headerp = true;
	}

	if (json_is_array(tup->obj.rdata)) {
		size_t slot, nslots;

		nslots = json_array_size(tup->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(tup->obj.rdata, slot);
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
	putchar('\n');
}

/* present_csv_summ -- render a summarize result as CSV.
 */
void
present_csv_summarize(pdns_tuple_ct tup,
		      const char *jsonbuf __attribute__ ((unused)),
		      size_t jsonlen __attribute__ ((unused)),
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
	DEBUG(4, true, "%s\n", json_dumps(tup->obj.main, JSON_INDENT(2)));

	if (encap != encap_saf) {
		tup->obj.cof_obj = tup->obj.main;
	} else {
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
		tup->rrname = json_string_value(tup->obj.rrname);
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
	return (NULL);

 ouch:
	assert(msg != NULL);
	tuple_unmake(tup);
	return (msg);
}

/* tuple_unmake -- deallocate the heap storage associated with one tuple.
 */
void
tuple_unmake(pdns_tuple_t tup) {
	json_decref(tup->obj.main);
}

/* data_blob -- process one deblocked json blob as a counted string.
 *
 * presents each blob and then frees it.
 * returns number of tuples processed (for now, 1 or 0).
 */
int
data_blob(query_t query, const char *buf, size_t len) {
	writer_t writer = query->writer;
	struct pdns_tuple tup;
	u_long first, last;
	const char *msg;
	int ret = 0;

	msg = tuple_make(&tup, buf, len);
	if (msg != NULL) {
		fputs(msg, stderr);
		fputc('\n', stderr);
		goto more;
	}

	if (encap == encap_saf) {
		if (tup.msg != NULL) {
			DEBUG(5, true, "data_blob tup.msg = %s\n", tup.msg);
			query->saf_msg = strdup(tup.msg);
		}

		if (tup.cond != NULL) {
			DEBUG(5, true, "data_blob tup.cond = %s\n", tup.cond);
			/* if we goto next now, this line will not be counted */
			if (strcmp(tup.cond, "begin") == 0) {
				query->saf_cond = sc_begin;
				goto next;
			} else if (strcmp(tup.cond, "ongoing") == 0) {
				/* "cond":"ongoing" key vals should
				 * be ignored but the rest of line used. */
				query->saf_cond = sc_ongoing;
			} else if (strcmp(tup.cond, "succeeded") == 0) {
				query->saf_cond = sc_succeeded;
				goto next;
			} else if (strcmp(tup.cond, "limited") == 0) {
				query->saf_cond = sc_limited;
				goto next;
			} else if (strcmp(tup.cond, "failed") == 0) {
				query->saf_cond = sc_failed;
				goto next;
			} else {
				/* use sc_missing for an invalid cond value  */
				query->saf_cond = sc_missing;
				fprintf(stderr,
					"%s: Unknown value for \"cond\": %s\n",
					program_name, tup.cond);
			}
		}

		/* A COF keepalive will have no "obj" but may have a "cond" or "msg". */
		if (tup.obj.saf_obj == NULL) {
			DEBUG(4, true, "COF object is empty, i.e. a keepalive\n");
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
		 * which are accessed as -k1 .. -k6 on the
		 * sort command line. we strip them off later
		 * when reading the result back. the reason
		 * for all this PDP11-era logic is to avoid
		 * having to store the full result in memory.
		 */
		char *dyn_rrname = sortable_rrname(&tup),
			*dyn_rdata = sortable_rdata(&tup);

		DEBUG(3, true, "dyn_rrname = '%s'\n", dyn_rrname);
		DEBUG(3, true, "dyn_rdata = '%s'\n", dyn_rdata);
		fprintf(writer->sort_stdin, "%lu %lu %lu %lu %s %s %*.*s\n",
			(unsigned long)first,
			(unsigned long)last,
			(unsigned long)(last - first),
			(unsigned long)tup.count,
			or_else(dyn_rrname, "n/a"),
			or_else(dyn_rdata, "n/a"),
			(int)len, (int)len, buf);
		DEBUG(2, true, "sort0: '%lu %lu %lu %lu %s %s %*.*s'\n",
			 (unsigned long)first,
			 (unsigned long)last,
			 (unsigned long)(last - first),
			 (unsigned long)tup.count,
			 or_else(dyn_rrname, "n/a"),
			 or_else(dyn_rdata, "n/a"),
			 (int)len, (int)len, buf);
		DESTROY(dyn_rrname);
		DESTROY(dyn_rdata);
	} else {
		(*presenter)(&tup, buf, len, writer);
	}

	ret = 1;
 next:
	tuple_unmake(&tup);
 more:
	return (ret);
}
