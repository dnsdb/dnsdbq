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

/* External. */

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

/* gettimeofday() does not appear on linux without this. */
#define _BSD_SOURCE

/* modern glibc will complain about the above if it doesn't see this. */
#define _DEFAULT_SOURCE

#include <sys/wait.h>
#include <sys/time.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

/* Types. */

#define MAIN_PROGRAM
#include "defs.h"
#include "netio.h"
#include "pdns.h"
#if WANT_PDNS_DNSDB
#include "pdns_dnsdb.h"
#endif
#if WANT_PDNS_CIRCL
#include "pdns_circl.h"
#endif
#include "sort.h"
#include "time.h"
#include "globals.h"
#undef MAIN_PROGRAM

#define QPARAM_GETOPT "A:B:L:l:cgG"

/* Forward. */

static void help(void);
static pdns_system_ct pick_system(const char *);
static void qdesc_debug(const char *, qdesc_ct);
static void qparam_debug(const char *, qparam_ct);
static __attribute__((noreturn)) void usage(const char *, ...);
static bool parse_long(const char *, long *);
static const char *qparam_ready(qparam_t);
static const char *qparam_option(int, const char *, qparam_t);
static verb_ct find_verb(const char *);
static void read_configs(void);
static void do_batch(FILE *, qparam_ct);
static const char *batch_options(const char *, qparam_t, qparam_ct);
static const char *batch_parse(char *, qdesc_t);
static char *makepath(mode_e, const char *, const char *,
		      const char *, const char *);
static query_t query_launcher(qdesc_ct, qparam_ct, writer_t);
static void launch(query_t, u_long, u_long, u_long, u_long);
static void ruminate_json(int, qparam_ct);
static const char *lookup_ok(void);
static const char *summarize_ok(void);

/* Constants. */

static const char * const conf_files[] = {
	"~/.isc-dnsdb-query.conf",
	"~/.dnsdb-query.conf",
	"/etc/isc-dnsdb-query.conf",
	"/etc/dnsdb-query.conf",
	NULL
};

const struct verb verbs[] = {
	/* note: element [0] of this array is the DEFAULT_VERB. */
	{ "lookup", "/lookup", lookup_ok,
	  present_text_lookup, present_json, present_csv_lookup },
	{ "summarize", "/summarize", summarize_ok,
	  present_text_summarize, present_json, present_csv_summarize },
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Private. */

static size_t ideal_buffer;

/* Public. */

int
main(int argc, char *argv[]) {
	struct qdesc qd = { .mode = no_mode };
	struct qparam qp = qparam_empty;
	bool info = false;
	int json_fd = -1;
	const char *msg;
	char *value;
	int ch;

	/* global dynamic initialization. */
	ideal_buffer = 4 * (size_t) sysconf(_SC_PAGESIZE);
	gettimeofday(&startup_time, NULL);
	if ((program_name = strrchr(argv[0], '/')) == NULL)
		program_name = argv[0];
	else
		program_name++;
	value = getenv(env_time_fmt);
	if (value != NULL && strcasecmp(value, "iso") == 0)
		iso8601 = true;
	pverb = &verbs[DEFAULT_VERB];

	/* process the command line options. */
	while ((ch = getopt(argc, argv,
			    "R:r:N:n:i:M:u:p:t:b:k:J:O:V:"
			    "dfhIjmqSsUv" QPARAM_GETOPT))
	       != -1)
	{
		switch (ch) {
		case 'A': case 'B': case 'c':
		case 'g': case 'G':
		case 'l': case 'L':
			if ((msg = qparam_option(ch, optarg, &qp)) != NULL)
				usage(msg);
			break;
		case 'R': {
			if (qd.mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(qd.thing == NULL);
			qd.mode = raw_rrset_mode;

			const char *p = strchr(optarg, '/');
			if (p != NULL) {
				if (qd.rrtype != NULL ||
				    qd.bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-R cannot contain a slash");

				const char *q = strchr(p + 1, '/');
				if (q != NULL) {
					qd.bailiwick = strdup(q + 1);
					qd.rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					qd.rrtype = strdup(p + 1);
				}
				qd.thing = strndup(optarg,
						      (size_t)(p - optarg));
			} else {
				qd.thing = strdup(optarg);
			}
			break;
		    }
		case 'r': {
			if (qd.mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(qd.thing == NULL);
			qd.mode = rrset_mode;

			const char *p = strchr(optarg, '/');
			if (p != NULL) {
				if (qd.rrtype != NULL ||
				    qd.bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-r cannot contain a slash");

				const char *q = strchr(p + 1, '/');
				if (q != NULL) {
					qd.bailiwick = strdup(q + 1);
					qd.rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					qd.rrtype = strdup(p + 1);
				}
				qd.thing = strndup(optarg,
						      (size_t)(p - optarg));
			} else {
				qd.thing = strdup(optarg);
			}
			break;
		    }
		case 'N': {
			if (qd.mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(qd.thing == NULL);
			qd.mode = raw_name_mode;

			const char *p = strchr(optarg, '/');
			if (p != NULL) {
				if (qd.rrtype != NULL ||
				    qd.bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-N cannot contain a slash");

				const char *q = strchr(p + 1, '/');
				if (q != NULL) {
					qd.bailiwick = strdup(q + 1);
					qd.rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					qd.rrtype = strdup(p + 1);
				}
				qd.thing = strndup(optarg,
						      (size_t)(p - optarg));
			} else {
				qd.thing = strdup(optarg);
			}
			break;
		    }
		case 'n': {
			if (qd.mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(qd.thing == NULL);
			qd.mode = name_mode;

			const char *p = strchr(optarg, '/');
			if (p != NULL) {
				if (qd.rrtype != NULL ||
				    qd.bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-n cannot contain a slash");

				const char *q = strchr(p + 1, '/');
				if (q != NULL) {
					qd.bailiwick = strdup(q + 1);
					qd.rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					qd.rrtype = strdup(p + 1);
				}
				qd.thing = strndup(optarg,
						      (size_t)(p - optarg));
			} else {
				qd.thing = strdup(optarg);
			}
			break;
		    }
		case 'i': {
			if (qd.mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(qd.thing == NULL);
			qd.mode = ip_mode;

			const char *p = strchr(optarg, '/');
			if (p != NULL) {
				qd.thing = strndup(optarg,
						      (size_t)(p - optarg));
				qd.pfxlen = strdup(p + 1);
			} else {
				qd.thing = strdup(optarg);
			}
			break;
		    }
		case 'V': {
			pverb = find_verb(optarg);
			if (pverb == NULL)
				usage("Unsupported verb for -V argument");
			break;
		    }
		case 'M':
			if (!parse_long(optarg, &max_count) || (max_count <= 0))
				usage("-M must be positive");
			break;
		case 'O':
			if (!parse_long(optarg, &offset) || (offset < 0))
				usage("-O must be zero or positive");
			break;
		case 'u':
			if ((psys = pick_system(optarg)) == NULL)
				usage("-u must refer to a pdns system");
			break;
		case 'U':
			donotverify = true;
			break;
		case 'p':
			if (strcasecmp(optarg, "json") == 0)
				presentation = pres_json;
			else if (strcasecmp(optarg, "csv") == 0)
				presentation = pres_csv;
			else if (strcasecmp(optarg, "text") == 0 ||
				 strcasecmp(optarg, "dns") == 0)
				presentation = pres_text;
			else
				usage("-p must specify json, text, or csv");
			break;
		case 't':
			if (qd.rrtype != NULL)
				usage("can only specify rrtype one way");
			qd.rrtype = strdup(optarg);
			break;
		case 'b':
			if (qd.bailiwick != NULL)
				usage("can only specify bailiwick one way");
			qd.bailiwick = strdup(optarg);
			break;
		case 'k': {
			if (sorting == no_sort)
				usage("-k must be preceded by -s or -S");

			char *saveptr = NULL;
			const char *tok;
			for (tok = strtok_r(optarg, ",", &saveptr);
			     tok != NULL;
			     tok = strtok_r(NULL, ",", &saveptr))
			{
				if (find_sort_key(tok) != NULL)
					usage("Each sort key may only be "
					      "specified once");

				if ((msg = add_sort_key(tok)) != NULL)
					usage(msg);
			}
			break;
		    }
		case 'J':
			if (strcmp(optarg, "-") == 0)
				json_fd = STDIN_FILENO;
			else
				json_fd = open(optarg, O_RDONLY);
			if (json_fd < 0)
				my_panic(true, optarg);
			break;
		case 'd':
			debug_level++;
			break;
		case 'j':
			presentation = pres_json;
			break;
		case 'f':
			switch (batching) {
			case batch_none:
				batching = batch_original;
				break;
			case batch_original:
				batching = batch_verbose;
				break;
			case batch_verbose:
				/* FALLTHROUGH */
			default:
				usage("too many -f options");
			}
			break;
		case 'm':
			multiple = true;
			break;
		case 's':
			sorting = normal_sort;
			break;
		case 'S':
			sorting = reverse_sort;
			break;
		case 'I':
			info = true;
			break;
		case 'v':
			printf("%s: version %s\n", program_name, id_version);
			my_exit(0);
		case 'q':
			quiet = true;
			break;
		case 'h':
			help();
			my_exit(0);
		default:
			usage("unrecognized option");
		}
	}
	argc -= optind;
	if (argc != 0)
		usage("there are no non-option arguments to this program");
	argv = NULL;

	/* recondition various options for HTML use. */
	CURL *easy = curl_easy_init();
	escape(easy, &qd.thing);
	escape(easy, &qd.rrtype);
	escape(easy, &qd.bailiwick);
	escape(easy, &qd.pfxlen);
	curl_easy_cleanup(easy);
	easy = NULL;

	if ((msg = qparam_ready(&qp)) != NULL)
		usage(msg);

	/* optionally dump program options as interpreted. */
	if (debug_level >= 1) {
		qdesc_debug("main", &qd);
		qparam_debug("main", &qp);
		debug(true, "batching=%d, multiple=%d\n",
		      batching != false, multiple != false);
	}

	/* select presenter. */
	switch (presentation) {
	case pres_text:
		presenter = pverb->text;
		break;
	case pres_json:
		presenter = pverb->json;
		break;
	case pres_csv:
		presenter = pverb->csv;
		break;
	default:
		abort();
	}

	/* get to final readiness; in particular, get psys set. */
	if (sorting != no_sort)
		sort_ready();
	read_configs();
	if (psys == NULL)
		usage("neither " DNSDBQ_SYSTEM " nor -u were specified.");

	/* validate some interrelated options. */
	if (multiple && batching == batch_none)
		usage("using -m without -f makes no sense.");
	if (sorting == no_sort && json_fd == -1 && qp.complete)
		usage("warning: -A and -B w/o -c or -J reqs -s or -S");
	if ((msg = (*pverb->ok)()) != NULL)
		usage(msg);
	if ((msg = psys->verb_ok(pverb->name)) != NULL)
		usage(msg);

	/* get some input from somewhere, and use it to drive our output. */
	if (json_fd != -1) {
		/* read a JSON file. */
		if (qd.mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -J");
		if (batching != batch_none)
			usage("can't mix -f with -J");
		if (qd.bailiwick != NULL)
			usage("can't mix -b with -J");
		if (info)
			usage("can't mix -I with -J");
		if (qd.rrtype != NULL)
			usage("can't mix -t with -J");
		if (pverb != &verbs[DEFAULT_VERB])
			usage("can't mix -V with -J");
		if (max_count > 0)
			usage("can't mix -M with -J");
		if (qp.gravel)
			usage("can't mix -g with -J");
		if (offset != 0)
			usage("can't mix -O with -J");
		ruminate_json(json_fd, &qp);
		close(json_fd);
	} else if (batching != batch_none) {
		/* drive via a batch file. */
		if (qd.mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -f");
		if (qd.bailiwick != NULL)
			usage("can't mix -b with -f");
		if (qd.rrtype != NULL)
			usage("can't mix -t with -f");
		if (info)
			usage("can't mix -I with -f");
		if ((msg = psys->ready()) != NULL)
			usage(msg);
		make_curl();
		do_batch(stdin, &qp);
		unmake_curl();
	} else if (info) {
		/* use the "info" verb. */
		if (qd.mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -I");
		if (presentation != pres_text && presentation != pres_json)
			usage("info must be presented in json or text format");
		if (qd.bailiwick != NULL)
			usage("can't mix -b with -I");
		if (qd.rrtype != NULL)
			usage("can't mix -t with -I");
		if (psys->info_req == NULL || psys->info_blob == NULL)
			usage("there is no 'info' for this service");
		if ((msg = psys->ready()) != NULL)
			usage(msg);
		make_curl();
		psys->info_req();
		unmake_curl();
	} else {
		/* do a LHS or RHS lookup of some kind. */
		if (qd.mode == no_mode)
			usage("must specify -r, -n, -i, or -R"
			      " unless -f or -J is used");
		if (qd.bailiwick != NULL) {
			if (qd.mode == ip_mode)
				usage("can't mix -b with -i");
			if (qd.mode == raw_rrset_mode)
				usage("can't mix -b with -R");
			if (qd.mode == raw_name_mode)
				usage("can't mix -b with -N");
			if (qd.mode == name_mode)
				usage("can't mix -b with -n");
		}
		if (qd.mode == ip_mode && qd.rrtype != NULL)
			usage("can't mix -i with -t");

		if ((msg = psys->ready()) != NULL)
			usage(msg);
		make_curl();
		writer_t writer = writer_init(qp.output_limit);
		(void) query_launcher(&qd, &qp, writer);
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
		unmake_curl();
	}

	/* clean up and go home. */
	DESTROY(qd.thing);
	DESTROY(qd.rrtype);
	DESTROY(qd.bailiwick);
	DESTROY(qd.pfxlen);
	my_exit(exit_code);
}

/* debug -- at the moment, dump to stderr.
 */
void
debug(bool want_header, const char *fmtstr, ...) {
	va_list ap;

	va_start(ap, fmtstr);
	if (want_header)
		fputs("debug: ", stderr);
	vfprintf(stderr, fmtstr, ap);
	va_end(ap);
}

/* my_exit -- close or destroy global objects, then exit.
 */
__attribute__((noreturn)) void
my_exit(int code) {
	/* writers and readers which are still known, must be freed. */
	unmake_writers();

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	/* globals which may have been initialized, are to be freed. */
	if (psys != NULL)
		psys->destroy();

	/* sort key specifications and computations, are to be freed. */
	sort_destroy();

	/* terminate process. */
	DEBUG(1, true, "about to call exit(%d)\n", code);
	exit(code);
}

/* my_panic -- display an error on diagnostic output stream, exit ungracefully
 */
__attribute__((noreturn)) void
my_panic(bool want_perror, const char *s) {
	fprintf(stderr, "%s: ", program_name);
	if (want_perror)
		perror(s);
	else
		fprintf(stderr, "%s\n", s);
	my_exit(1);
}

/* or_else -- return one pointer or else the other. */
const char *
or_else(const char *p, const char *or_else) {
	if (p != NULL)
		return p;
	return or_else;
}

/* Private. */

/* help -- display a brief usage-help text; then exit.
 *
 * this goes to stdout since we can expect it not to be piped unless to $PAGER.
 */
static void
help(void) {
	verb_ct v;

	printf("usage: %s [-cdfgGhIjmqSsUv] [-p dns|json|csv]\n",
	       program_name);
	puts("\t[-k (first|last|count|name|data)[,...]]\n"
	     "\t[-l QUERY-LIMIT] [-L OUTPUT-LIMIT] [-A after] [-B before]\n"
	     "\t[-u system] [-O offset] [-V verb] [-M max_count] {\n"
	     "\t\t-f |\n"
	     "\t\t-J inputfile |\n"
	     "\t\t[-t rrtype] [-b bailiwick] {\n"
	     "\t\t\t-r OWNER[/TYPE[/BAILIWICK]] |\n"
	     "\t\t\t-n NAME[/TYPE] |\n"
	     "\t\t\t-i IP[/PFXLEN] |\n"
	     "\t\t\t-N RAW-NAME-DATA[/TYPE]\n"
	     "\t\t\t-R RAW-OWNER-DATA[/TYPE[/BAILIWICK]]\n"
	     "\t\t}\n"
	     "\t}");
	puts("for -A and -B, use absolute format YYYY-MM-DD[ HH:MM:SS],\n"
	     "\tor relative format %dw%dd%dh%dm%ds.\n"
	     "use -c to get complete (strict) time matching for -A and -B.\n"
	     "use -d one or more times to ramp up the diagnostic output.\n"
	     "for -f, stdin must contain lines of the following forms:\n"
	     "\trrset/name/NAME[/TYPE[/BAILIWICK]]\n"
	     "\trrset/raw/HEX-PAIRS[/RRTYPE[/BAILIWICK]]\n"
	     "\trdata/name/NAME[/TYPE]\n"
	     "\trdata/ip/ADDR[,PFXLEN]\n"
	     "\trdata/raw/HEX-PAIRS[/RRTYPE]\n"
	     "\t(output format will depend on -p or -j, framed by '--'.)\n"
	     "\t(with -ff, framing will be '++ $cmd', '-- $stat ($code)'.\n"
	     "use -g to get graveled results (default is -G, rocks).\n"
	     "use -h to reliably display this helpful text.\n"
	     "use -I to see a system-specific account/key summary.\n"
	     "for -J, input format is newline-separated JSON, "
	     "as from -j output.\n"
	     "use -j as a synonym for -p json.\n"
	     "use -M # to end a summarize op when count exceeds threshold.\n"
	     "use -m with -f for multiple upstream queries in single result.\n"
	     "use -m with -f -f for multiple upstream queries out of order.\n"
	     "use -O # to skip this many results in what is returned.\n"
	     "use -q for warning reticence.\n"
	     "use -s to sort in ascending order, "
	     "or -S for descending order.\n"
	     "\t-s/-S can be repeated before several -k arguments.\n"
	     "use -U to turn off SSL certificate verification.\n"
	     "use -v to show the program version.");
	puts("for -u, system must be one of:");
	puts("\tdnsdb");
#if WANT_PDNS_CIRCL
	puts("\tcircl");
#endif
	puts("for -V, verb must be one of:");
	for (v = verbs; v->name != NULL; v++)
		printf("\t%s\n", v->name);
	puts("\nGetting Started:\n"
	     "\tAdd your API key to ~/.dnsdb-query.conf like this:\n"
	     "\t\tAPIKEY=\"YOURAPIKEYHERE\"");
	printf("\nTry   man %s  for full documentation.\n", program_name);
}

static pdns_system_ct
pick_system(const char *name) {
#if WANT_PDNS_DNSDB
	if (strcmp(name, "dnsdb") == 0)
		return pdns_dnsdb();
#endif
#if WANT_PDNS_CIRCL
	if (strcmp(name, "circl") == 0)
		return pdns_circl();
#endif
	return NULL;
}

/* qdesc_debug -- dump a qdesc.
 */
static void
qdesc_debug(const char *where, qdesc_ct qdp) {
	debug(true, "qdesc(%s)[", where);

	const char *sep = "\040";
	if (qdp->thing != NULL) {
		debug(true, "%sth '%s'", sep, qdp->thing);
		sep = ",\040";
	}
	if (qdp->rrtype != NULL) {
		debug(true, "%srr '%s'\n", sep, qdp->rrtype);
		sep = ",\040";
	}
	if (qdp->bailiwick != NULL) {
		debug(true, "%sbw '%s'\n", sep, qdp->bailiwick);
		sep = ",\040";
	}
	if (qdp->pfxlen != NULL) {
		debug(true, "%spfx '%s'\n", sep, qdp->pfxlen);
		sep = ",\040";
	}
	debug(false, " ]\n");
}

/* qparam_debug -- dump a qparam.
 */
static void
qparam_debug(const char *where, qparam_ct qpp) {
	debug(true, "qparam(%s)[", where);

	const char *sep = "\040";
	if (qpp->after != 0) {
		debug(false, "%s-A%ld(%s)",
		      sep, qpp->after, time_str(qpp->after, false));
		sep = "\n\t";
	}
	if (qpp->before != 0) {
		debug(false, "%s-B%ld(%s)",
		      sep, qpp->before, time_str(qpp->before, false));
		sep = "\n\t";
	}
	if (qpp->query_limit != -1) {
		debug(false, "%s-l%ld", sep, qpp->query_limit);
		sep = "\040";
	}
	if (qpp->output_limit != -1) {
		debug(false, "%s-L%ld", sep, qpp->output_limit);
		sep = "\040";
	}
	if (qpp->complete) {
		debug(false, "%s-c", sep);
		sep = "\040";
	}
	if (qpp->gravel) {
		debug(false, "%s-g", sep);
		sep = "\040";
	}
	debug(false, "\040]\n");
}

/* usage -- display a usage error message, brief usage help text; then exit.
 *
 * this goes to stderr in case stdout has been piped or redirected.
 */
static __attribute__((noreturn)) void
usage(const char *fmtstr, ...) {
	va_list ap;

	va_start(ap, fmtstr);
	fputs("error: ", stderr);
	vfprintf(stderr, fmtstr, ap);
	va_end(ap);
	fputs("\n\n", stderr);
	fprintf(stderr,
		"try   %s -h   for a short description of program usage.\n",
		program_name);
	my_exit(1);
}

/* parse a base 10 long value.	Return true if ok, else return false.
 */
static bool
parse_long(const char *in, long *out) {
	char *ep;
	long result;

	/* "The strtol() function shall not change the setting of errno
	 * if successful." (IEEE Std 1003.1, 2004 Edition)
	 */
	errno = 0;
	result = strtol(in, &ep, 10);
	if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) ||
	    (errno != 0 && result == 0) ||
	    (ep == in))
		return false;
	*out = result;
	return true;
}

/* qparam_ready -- check and possibly adjust the contents of a qparam.
 */
static const char *
qparam_ready(qparam_t qpp) {
	if (qpp->output_limit == -1 && qpp->query_limit != -1 && !multiple)
		qpp->output_limit = qpp->query_limit;
	if (qpp->after != 0 && qpp->before != 0) {
		if (qpp->after > qpp->before)
			return "-A value must be before -B value (for now)";
	}
	if (qpp->complete && qpp->after == 0 && qpp->before == 0)
		return "-c without -A or -B makes no sense.";
	return NULL;
}

/* qparam_option -- process one command line option related to a qparam
 */
static const char *
qparam_option(int opt, const char *arg, qparam_t qpp) {
	switch (opt) {
	case 'A':
		if (!time_get(arg, &qpp->after) || qpp->after == 0UL)
			return "bad -A timestamp";
		break;
	case 'B':
		if (!time_get(arg, &qpp->before) || qpp->before == 0UL)
			return "bad -B timestamp";
		break;
	case 'c':
		qpp->complete = true;
		break;
	case 'g':
		qpp->gravel = true;
		break;
	case 'G':
		qpp->gravel = false;
		break;
	case 'l':
		if (!parse_long(arg, &qpp->query_limit) ||
		    (qpp->query_limit < 0))
			return "-l must be zero or positive";
		break;
	case 'L':
		if (!parse_long(arg, &qpp->output_limit) ||
		    (qpp->output_limit <= 0))
			return "-L must be positive";
		break;
	}
	return NULL;
}

/* lookup_ok -- validate command line options for 'lookup'.
 */
static const char *
lookup_ok(void) {
	/* TODO too many local variables would need to be global to check
	 * more here.
	 */
	if (max_count > 0)
		return "max_count only allowed for a summarize verb";
	return NULL;
}

/* summarize_ok -- validate commandline options for 'summarize'.
 */
static const char *
summarize_ok(void) {
	if (sorting != no_sort)
		return "Sorting with a summarize verb makes no sense";
	return NULL;
}

/* find_verb -- locate a verb by option parameter
 */
static verb_ct
find_verb(const char *option) {
	verb_ct v;

	for (v = verbs; v->name != NULL; v++)
		if (strcasecmp(option, v->name) == 0)
			return (v);
	return (NULL);
}

/* read_configs -- try to find a config file in static path, then parse it.
 */
static void
read_configs(void) {
	const char * const *conf;
	char *cf = NULL;

	for (conf = conf_files; *conf != NULL; conf++) {
		wordexp_t we;

		wordexp(*conf, &we, WRDE_NOCMD);
		cf = strdup(we.we_wordv[0]);
		wordfree(&we);
		if (access(cf, R_OK) == 0) {
			DEBUG(1, true, "conf found: '%s'\n", cf);
			break;
		}
		DESTROY(cf);
	}
	if (cf != NULL) {
		char *cmd, *line;
		size_t n;
		int x, l;
		FILE *f;

		x = asprintf(&cmd,
			     ". %s;"
			     "echo dnsdbq system $" DNSDBQ_SYSTEM ";"
#if WANT_PDNS_DNSDB
			     "echo dnsdb apikey $APIKEY;"
			     "echo dnsdb server $DNSDB_SERVER;"
#endif
#if WANT_PDNS_CIRCL
			     "echo circl apikey $CIRCL_AUTH;"
			     "echo circl server $CIRCL_SERVER;"
#endif
			     "exit", cf);
		DESTROY(cf);
		if (x < 0)
			my_panic(true, "asprintf");
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
				fprintf(stderr,
					"%s: conf line #%d: too long\n",
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
				if (psys == NULL &&
				    strcmp(tok2, "system") == 0)
				{
					psys = pick_system(tok3);
					if (psys == NULL) {
						fprintf(stderr,
							"%s: unknown %s %s\n",
							program_name,
							DNSDBQ_SYSTEM,
							tok3);
						my_exit(1);
					}
				}
				continue;
			}

			/* this is the last point where psys can be null. */
			if (psys == NULL) {
				/* first match wins and is sticky. */
				if ((psys = pick_system(tok1)) == NULL)
					continue;
				DEBUG(1, true, "picked system %s\n", tok1);
			}

			/* if this variable is for this system, consume it. */
			if (strcmp(tok1, psys->name) == 0) {
				DEBUG(1, true, "line #%d: sets %s|%s|%s\n",
				      l, tok1, tok2,
				      strcmp(tok2, "apikey") == 0
				      	? "..." : tok3);
				msg = psys->setval(tok2, tok3);
				if (msg != NULL)
					usage(msg);
			}
		}
		DESTROY(line);
		pclose(f);
	}
}


/* do_batch -- implement "filter" mode, reading commands from a batch file.
 *
 * the 'after' and 'before' arguments are from -A and -B and are defaults.
 */
static void
do_batch(FILE *f, qparam_ct qpp) {
	struct qparam qp = *qpp;
	writer_t writer = NULL;
	char *command = NULL;
	size_t n = 0;

	/* if doing multiple upstreams, start a writer. */
	if (multiple)
		writer = writer_init(qp.output_limit);

	while (getline(&command, &n, f) > 0) {
		const char *msg;
		struct qdesc qd;
		char *nl;

		/* the last line of the file may not have a newline. */
		nl = strchr(command, '\n');
		if (nl != NULL)
			*nl = '\0';

		DEBUG(1, true, "do_batch(%s)\n", command);

		/* if this is a $OPTIONS, parse it and change our qparams. */
		if (strncasecmp(command, "$options",
				(sizeof "$options") - 1) == 0)
		{
			if ((msg = batch_options(command, &qp, qpp)) != NULL)
				fprintf(stderr, "%s: warning: "
					"batch option parse error: %s\n",
					program_name, msg);
			continue;
		}

		/* if not parallelizing, start a writer here instead. */
		if (!multiple)
			writer = writer_init(qp.output_limit);

		/* crack the batch line if possible. */
		msg = batch_parse(command, &qd);
		if (msg != NULL) {
			fprintf(stderr, "%s: batch entry parse error: %s\n",
				program_name, msg);
		} else {
			/* start one or two curl jobs based on this search. */
			query_t query = query_launcher(&qd, &qp, writer);

			/* if merging, drain some jobs; else, drain all jobs.
			 */
			if (multiple)
				io_engine(MAX_JOBS);
			else
				io_engine(0);
			if (query->status != NULL &&
			    batching != batch_verbose)
			{
				assert(query->message != NULL);
				fprintf(stderr,
					"%s: batch line status: %s (%s)\n",
					program_name,
					query->status, query->message);
			}
		}

		/* think about showing the end-of-object separator. */
		if (!multiple) {
			switch (batching) {
			case batch_none:
				break;
			case batch_original:
				assert(writer->ps_buf == NULL &&
				       writer->ps_len == 0);
				writer->ps_buf = strdup("--\n");
				writer->ps_len = strlen(writer->ps_buf);
				break;
			case batch_verbose:
				/* query_done() will do this. */
				break;
			default:
				abort();
			}
			writer_fini(writer);
			writer = NULL;
			fflush(stdout);
		}
	}
	DESTROY(command);

	/* if parallelized, run remaining jobs to completion, then finish up.
	 */
	if (multiple) {
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
	}
}

/* batch_options -- parse a $OPTIONS line out of a batch file.
 */
static const char *
batch_options(const char *optstr, qparam_t options, qparam_ct dflt) {
	char **opts = calloc(strlen(optstr) + 1, sizeof(char *));
	struct qparam save = *options;
	char **opt = opts;
	const char *msg;
	char *tok;
	int ch;

	char *temp = strdup(optstr);
	char *saveptr = NULL;
	/* crack the option string based on space or tab delimiters. */
	for (tok = strtok_r(temp, "\040\t", &saveptr);
	     tok != NULL;
	     tok = strtok_r(NULL, "\040\t", &saveptr))
	{
		/* dispense with extra spaces and tabs (empty fields). */
		if (*tok == '\0')
			continue;
		*opt++ = tok;
	}

	/* if no options were specified (e.g., $options\n), restore defaults. */
	msg = NULL;
	if ((opt - opts) == 1) {
		DEBUG(2, true, "default options restored\n");
		*options = *dflt;
	} else {
		/* use getopt() to parse the cracked array. */
#ifdef linux
		optind = 0;
#else
		optind = 1;
		optreset = 1;
#endif
		while ((ch = getopt((int)(opt - opts), opts, QPARAM_GETOPT))
		       != -1)
		{
			if ((msg = qparam_option(ch, optarg, options)) != NULL)
				break;
		}
	}
	/* if an error occured, reset options to saved values. */
	if (msg != NULL) {
		*options = save;
	} else {
		/* otherwise consider reporting the new options. */
		if (debug_level >= 1)
			qparam_debug("batch", options);
	}
	/* done. */
	DESTROY(opts);
	DESTROY(temp);
	return msg;
}

/* batch_parse -- turn one line from a -f batch into a (struct query).
 */
static const char *
batch_parse(char *line, qdesc_t qdp) {
	struct qdesc qd = (struct qdesc) { };
	char *saveptr = NULL;
	char *t;

	if ((t = strtok_r(line, "/", &saveptr)) == NULL)
		return "too few terms";
	if (strcmp(t, "rrset") == 0) {
		if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
			return "missing term after 'rrset/'";
		if (strcmp(t, "name") == 0) {
			qd.mode = rrset_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rrset/name/'";
			qd.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				qd.rrtype = t;
				if ((t = strtok_r(NULL, "/", &saveptr))
				    != NULL)
				{
					qd.bailiwick = t;
				}
			}
		} else if (strcmp(t, "raw") == 0) {
			qd.mode = raw_rrset_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rrset/raw/'";
			qd.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				qd.rrtype = t;
				if ((t = strtok_r(NULL, "/", &saveptr))
				    != NULL)
				{
					qd.bailiwick = t;
				}
			}
		} else {
			return "unrecognized term after 'rrset/'";
		}
	} else if (strcmp(t, "rdata") == 0) {
		if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
			return "missing term after 'rdata/'";
		if (strcmp(t, "name") == 0) {
			qd.mode = name_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/name/'";
			qd.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				qd.rrtype = t;
			}
		} else if (strcmp(t, "raw") == 0) {
			qd.mode = raw_name_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/raw/'";
			qd.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				qd.rrtype = t;
			}
		} else if (strcmp(t, "ip") == 0) {
			qd.mode = ip_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/ip/'";
			qd.thing = t;
		} else {
			return "unrecognized term after 'rdata/'";
		}
	} else {
		return "unrecognized initial term";
	}
	t = strtok_r(NULL, "/", &saveptr);
	if (t != NULL)
		return "extra garbage";
	*qdp = qd;
	return NULL;
}

/* makepath -- make a RESTful URI that describes these search parameters.
 */
static char *
makepath(mode_e mode, const char *name, const char *rrtype,
	 const char *bailiwick, const char *pfxlen)
{
	char *command;
	int x;

	switch (mode) {
	case rrset_mode:
		if (rrtype != NULL && bailiwick != NULL)
			x = asprintf(&command, "rrset/name/%s/%s/%s",
				     name, rrtype, bailiwick);
		else if (rrtype != NULL)
			x = asprintf(&command, "rrset/name/%s/%s",
				     name, rrtype);
		else if (bailiwick != NULL)
			x = asprintf(&command, "rrset/name/%s/ANY/%s",
				     name, bailiwick);
		else
			x = asprintf(&command, "rrset/name/%s",
				     name);
		if (x < 0)
			my_panic(true, "asprintf");
		break;
	case name_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rdata/name/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rdata/name/%s",
				     name);
		if (x < 0)
			my_panic(true, "asprintf");
		break;
	case ip_mode:
		if (pfxlen != NULL)
			x = asprintf(&command, "rdata/ip/%s,%s",
				     name, pfxlen);
		else
			x = asprintf(&command, "rdata/ip/%s",
				     name);
		if (x < 0)
			my_panic(true, "asprintf");
		break;
	case raw_rrset_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rrset/raw/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rrset/raw/%s",
				     name);
		if (x < 0)
			my_panic(true, "asprintf");
		break;
	case raw_name_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rdata/raw/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rdata/raw/%s",
				     name);
		if (x < 0)
			my_panic(true, "asprintf");
		break;
	case no_mode:
		/*FALLTHROUGH*/
	default:
		abort();
	}
	return (command);
}

/* query_launcher -- fork off some curl jobs via launch() for this query.
 */
static query_t
query_launcher(qdesc_ct qdp, qparam_ct qpp, writer_t writer) {
	query_t query = NULL;

	CREATE(query, sizeof(struct query));
	query->writer = writer;
	query->params = *qpp;
	writer = NULL;
	query->next = query->writer->queries;
	query->writer->queries = query;
	query->command = makepath(qdp->mode, qdp->thing, qdp->rrtype,
				  qdp->bailiwick, qdp->pfxlen);

	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (qpp->after != 0 && qpp->before != 0) {
		if (qpp->complete) {
			/* each db tuple must be enveloped by time fence. */
			launch(query, qpp->after, 0, 0, qpp->before);
		} else {
			/* we need tuples that end after fence start... */
			launch(query, 0, 0, qpp->after, 0);
			/* ...and that begin before the time fence end. */
			launch(query, 0, qpp->before, 0, 0);
			/* and we will filter in reader_func() to
			 * select only those tuples which either:
			 * ...(start within), or (end within), or
			 * ...(start before and end after).
			 */
		}
	} else if (qpp->after != 0) {
		if (qpp->complete) {
			/* each db tuple must begin after the fence-start. */
			launch(query, qpp->after, 0, 0, 0);
		} else {
			/* each db tuple must end after the fence-start. */
			launch(query, 0, 0, qpp->after, 0);
		}
	} else if (qpp->before != 0) {
		if (qpp->complete) {
			/* each db tuple must end before the fence-end. */
			launch(query, 0, 0, 0, qpp->before);
		} else {
			/* each db tuple must begin before the fence-end. */
			launch(query, 0, qpp->before, 0, 0);
		}
	} else {
		/* no time fencing. */
		launch(query, 0, 0, 0, 0);
	}
	return query;
}

/* launch -- actually launch a query job, given a command and time fences.
 */
static void
launch(query_t query,
       u_long first_after, u_long first_before,
       u_long last_after, u_long last_before)
{
	qparam_ct qpp = &query->params;
	char *url, *tmp, sep;
	int x;

	url = psys->url(query->command, &sep, qpp);
	if (url == NULL)
		my_exit(1);

	if (qpp->query_limit != -1) {
		x = asprintf(&tmp, "%s%c" "limit=%ld",
			     url, sep, qpp->query_limit);
		if (x < 0) {
			perror("asprintf");
			DESTROY(url);
			my_exit(1);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (first_after != 0) {
		x = asprintf(&tmp, "%s%c" "time_first_after=%lu",
			     url, sep, (u_long)first_after);
		if (x < 0) {
			perror("asprintf");
			DESTROY(url);
			my_exit(1);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (first_before != 0) {
		x = asprintf(&tmp, "%s%c" "time_first_before=%lu",
			     url, sep, (u_long)first_before);
		if (x < 0) {
			perror("asprintf");
			DESTROY(url);
			my_exit(1);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (last_after != 0) {
		x = asprintf(&tmp, "%s%c" "time_last_after=%lu",
			     url, sep, (u_long)last_after);
		if (x < 0) {
			perror("asprintf");
			DESTROY(url);
			my_exit(1);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (last_before != 0) {
		x = asprintf(&tmp, "%s%c" "time_last_before=%lu",
			     url, sep, (u_long)last_before);
		if (x < 0) {
			perror("asprintf");
			DESTROY(url);
			my_exit(1);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	DEBUG(1, true, "url [%s]\n", url);

	create_fetch(query, url);
}

/* ruminate_json -- process a json file from the filesys rather than the API.
 */
static void
ruminate_json(int json_fd, qparam_ct qpp) {
	fetch_t fetch = NULL;
	query_t query = NULL;
	void *buf = NULL;
	writer_t writer;
	ssize_t len;

	writer = writer_init(qpp->output_limit);
	CREATE(query, sizeof(struct query));
	query->writer = writer;
	query->params = *qpp;
	CREATE(fetch, sizeof(struct fetch));
	fetch->query = query;
	query->fetches = fetch;
	writer->queries = query;
	CREATE(buf, ideal_buffer);
	while ((len = read(json_fd, buf, sizeof buf)) > 0) {
		writer_func(buf, 1, (size_t)len, query->fetches);
	}
	DESTROY(buf);
	writer_fini(writer);
	writer = NULL;
}
