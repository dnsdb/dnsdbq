/* present_text -- render one pdns tuple in "dig" style ascii text.
 */
void
present_text(pdns_tuple_ct tup,
	     const char *jsonbuf __attribute__ ((unused)),
	     size_t jsonlen __attribute__ ((unused)),
	     FILE *outf)
{
	bool pflag, ppflag;
	const char *prefix;

	ppflag = false;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		fprintf(outf, ";; record times: %s",
			time_str(tup->time_first, iso8601));
		fprintf(outf, " .. %s\n",
			time_str(tup->time_last, iso8601));
		ppflag = true;
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		fprintf(outf, ";;   zone times: %s",
			time_str(tup->zone_first, iso8601));
		fprintf(outf, " .. %s\n",
			time_str(tup->zone_last, iso8601));
		ppflag = true;
	}

	/* Count and Bailiwick. */
	prefix = ";;";
	pflag = false;
	if (tup->obj.count != NULL) {
		fprintf(outf, "%s count: %lld", prefix, (long long)tup->count);
		prefix = ";";
		pflag = true;
		ppflag = true;
	}
	if (tup->obj.bailiwick != NULL) {
		fprintf(outf, "%s bailiwick: %s", prefix, tup->bailiwick);
		prefix = NULL;
		pflag = true;
		ppflag = true;
	}
	if (pflag)
		putc('\n', outf);

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
			fprintf(outf, "%s  %s  %s\n",
				tup->rrname, tup->rrtype, rdata);
			ppflag = true;
		}
	} else {
		fprintf(outf, "%s  %s  %s\n",
			tup->rrname, tup->rrtype, tup->rdata);
		ppflag = true;
	}

	/* Cleanup. */
	if (ppflag)
		putc('\n', outf);
}

/* present_text_summarize -- render summarize object in "dig" style ascii text.
 */
void
present_text_summarize(pdns_tuple_ct tup,
	     const char *jsonbuf __attribute__ ((unused)),
	     size_t jsonlen __attribute__ ((unused)),
	     FILE *outf)
{
	const char *prefix;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		fprintf(outf, ";; record times: %s",
			time_str(tup->time_first, iso8601));
		fprintf(outf, " .. %s\n",
			time_str(tup->time_last, iso8601));
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		fprintf(outf, ";;   zone times: %s",
			time_str(tup->zone_first, iso8601));
		fprintf(outf, " .. %s\n",
			time_str(tup->zone_last, iso8601));
		putc('\n', outf);
	}

	/* Count and Num_Results. */
	prefix = ";;";
	if (tup->obj.count != NULL) {
		fprintf(outf, "%s count: %lld",
			prefix, (long long)tup->count);
		prefix = ";";
	}
	if (tup->obj.num_results != NULL) {
		fprintf(outf, "%s num_results: %lld",
			prefix, (long long)tup->num_results);
		prefix = NULL;
	}

	putc('\n', outf);
}

/* present_json -- render one DNSDB tuple as newline-separated JSON.
 */
void
present_json(pdns_tuple_ct tup __attribute__ ((unused)),
	     const char *jsonbuf,
	     size_t jsonlen,
	     FILE *outf)
{
	fwrite(jsonbuf, 1, jsonlen, outf);
	putc('\n', outf);
}

/* present_json_summarize -- render one DNSDB tuple as newline-separated JSON.
 * Same implementation as present_json()
 */
void
present_json_summarize(pdns_tuple_ct tup __attribute__ ((unused)),
	     const char *jsonbuf,
	     size_t jsonlen,
	     FILE *outf)
{
	fwrite(jsonbuf, 1, jsonlen, outf);
	putc('\n', outf);
}

/* present_csv -- render one DNSDB tuple as comma-separated values (CSV).
 */
void
present_csv(pdns_tuple_ct tup,
	    const char *jsonbuf __attribute__ ((unused)),
	    size_t jsonlen __attribute__ ((unused)),
	    FILE *outf)
{
	static bool csv_headerp = false;

	if (!csv_headerp) {
		fprintf(outf,
			"time_first,time_last,zone_first,zone_last,"
			"count,bailiwick,"
			"rrname,rrtype,rdata\n");
		csv_headerp = true;
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
			present_csv_line(tup, rdata, outf);
		}
	} else {
		present_csv_line(tup, tup->rdata, outf);
	}
}

/* present_csv_line -- display a CSV for one rdatum out of an rrset.
 */
void
present_csv_line(pdns_tuple_ct tup,
		 const char *rdata,
		 FILE *outf)
{
	/* Timestamps. */
	if (tup->obj.time_first != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->time_first, iso8601));
	putc(',', outf);
	if (tup->obj.time_last != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->time_last, iso8601));
	putc(',', outf);
	if (tup->obj.zone_first != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->zone_first, iso8601));
	putc(',', outf);
	if (tup->obj.zone_last != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->zone_last, iso8601));
	putc(',', outf);

	/* Count and bailiwick. */
	if (tup->obj.count != NULL)
		fprintf(outf, "%lld", (long long) tup->count);
	putc(',', outf);
	if (tup->obj.bailiwick != NULL)
		fprintf(outf, "\"%s\"", tup->bailiwick);
	putc(',', outf);

	/* Records. */
	if (tup->obj.rrname != NULL)
		fprintf(outf, "\"%s\"", tup->rrname);
	putc(',', outf);
	if (tup->obj.rrtype != NULL)
		fprintf(outf, "\"%s\"", tup->rrtype);
	putc(',', outf);
	if (tup->obj.rdata != NULL)
		fprintf(outf, "\"%s\"", rdata);
	putc('\n', outf);
}

/* present_csv_summarize -- render a summarize result as CSV.
 */
void
present_csv_summarize(pdns_tuple_ct tup,
	    const char *jsonbuf __attribute__ ((unused)),
	    size_t jsonlen __attribute__ ((unused)),
	    FILE *outf)
{
	fprintf(outf,
		"time_first,time_last,zone_first,zone_last,"
		"count,num_results\n");

	/* Timestamps. */
	if (tup->obj.time_first != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->time_first, iso8601));
	putc(',', outf);
	if (tup->obj.time_last != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->time_last, iso8601));
	putc(',', outf);
	if (tup->obj.zone_first != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->zone_first, iso8601));
	putc(',', outf);
	if (tup->obj.zone_last != NULL)
		fprintf(outf, "\"%s\"", time_str(tup->zone_last, iso8601));
	putc(',', outf);

	/* Count and num_results. */
	if (tup->obj.count != NULL)
		fprintf(outf, "%lld", (long long) tup->count);
	putc(',', outf);
	if (tup->obj.num_results != NULL)
		fprintf(outf, "%lld", tup->num_results);
	putc('\n', outf);
}

/* tuple_make -- create one DNSDB tuple object out of a JSON object.
 */
const char *
tuple_make(pdns_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

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

	/* Timestamps. */
	tup->obj.zone_first = json_object_get(tup->obj.main,
					      "zone_time_first");
	if (tup->obj.zone_first != NULL) {
		if (!json_is_integer(tup->obj.zone_first)) {
			msg = "zone_time_first must be an integer";
			goto ouch;
		}
		tup->zone_first = (u_long)
			json_integer_value(tup->obj.zone_first);
	}
	tup->obj.zone_last = json_object_get(tup->obj.main, "zone_time_last");
	if (tup->obj.zone_last != NULL) {
		if (!json_is_integer(tup->obj.zone_last)) {
			msg = "zone_time_last must be an integer";
			goto ouch;
		}
		tup->zone_last = (u_long)
			json_integer_value(tup->obj.zone_last);
	}
	tup->obj.time_first = json_object_get(tup->obj.main, "time_first");
	if (tup->obj.time_first != NULL) {
		if (!json_is_integer(tup->obj.time_first)) {
			msg = "time_first must be an integer";
			goto ouch;
		}
		tup->time_first = (u_long)
			json_integer_value(tup->obj.time_first);
	}
	tup->obj.time_last = json_object_get(tup->obj.main, "time_last");
	if (tup->obj.time_last != NULL) {
		if (!json_is_integer(tup->obj.time_last)) {
			msg = "time_last must be an integer";
			goto ouch;
		}
		tup->time_last = (u_long)
			json_integer_value(tup->obj.time_last);
	}

	/* Count. */
	tup->obj.count = json_object_get(tup->obj.main, "count");
	if (tup->obj.count != NULL) {
		if (!json_is_integer(tup->obj.count)) {
			msg = "count must be an integer";
			goto ouch;
		}
		tup->count = json_integer_value(tup->obj.count);
	}
	/* Bailiwick. */
	tup->obj.bailiwick = json_object_get(tup->obj.main, "bailiwick");
	if (tup->obj.bailiwick != NULL) {
		if (!json_is_string(tup->obj.bailiwick)) {
			msg = "bailiwick must be a string";
			goto ouch;
		}
		tup->bailiwick = json_string_value(tup->obj.bailiwick);
	}
	/* num_results -- just for a summarize. */
	tup->obj.num_results = json_object_get(tup->obj.main, "num_results");
	if (tup->obj.num_results != NULL) {
		if (!json_is_integer(tup->obj.num_results)) {
			msg = "num_results must be an integer";
			goto ouch;
		}
		tup->num_results = json_integer_value(tup->obj.num_results);
	}

	/* Records. */
	tup->obj.rrname = json_object_get(tup->obj.main, "rrname");
	if (tup->obj.rrname != NULL) {
		if (!json_is_string(tup->obj.rrname)) {
			msg = "rrname must be a string";
			goto ouch;
		}
		tup->rrname = json_string_value(tup->obj.rrname);
	}
	tup->obj.rrtype = json_object_get(tup->obj.main, "rrtype");
	if (tup->obj.rrtype != NULL) {
		if (!json_is_string(tup->obj.rrtype)) {
			msg = "rrtype must be a string";
			goto ouch;
		}
		tup->rrtype = json_string_value(tup->obj.rrtype);
	}
	tup->obj.rdata = json_object_get(tup->obj.main, "rdata");
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

