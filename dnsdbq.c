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
#include "asinfo.h"
#include "defs.h"
#include "netio.h"
#include "pdns.h"
#include "sort.h"
#include "time.h"
#include "globals.h"
#undef MAIN_PROGRAM

#define QPARAM_GETOPT "A:B:L:l:O:cgG"

/* Forward. */

static void help(void);
static void qdesc_debug(const char *, qdesc_ct);
static void qparam_debug(const char *, qparam_ct);
static __attribute__((noreturn)) void usage(const char *, ...);
static bool parse_long(const char *, long *);
static const char *qparam_ready(qparam_t);
static const char *qparam_option(int, const char *, qparam_t);
static verb_ct find_verb(const char *);
static char *select_config(void);
static void do_batch(FILE *, qparam_ct);
static const char *batch_options(const char *, qparam_t, qparam_ct);
static const char *batch_parse(char *, qdesc_t);
static char *makepath(mode_e, const char *, const char *,
		      const char *, const char *);
static query_t query_launcher(qdesc_ct, qparam_ct, writer_t);
static void launch(query_t, pdns_fence_ct);
static void ruminate_json(int, qparam_ct);
static const char *lookup_ok(void);
static const char *summarize_ok(void);
static const char *check_7bit(const char *);

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
	  present_text_lookup,
	  present_json_lookup,
	  present_csv_lookup },
	{ "summarize", "/summarize", summarize_ok,
	  present_text_summarize,
	  present_json_summarize,
	  present_csv_summarize },
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Private. */

static size_t ideal_buffer;
static bool allow_8bit = false;

/* Public. */

int
main(int argc, char *argv[]) {
	struct qdesc qd = { .mode = no_mode };
	struct qparam qp = qparam_empty;
	char *picked_system = NULL;
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

	value = getenv(env_config_file);
	if (value != NULL)
		config_file = strdup(value);

	pverb = &verbs[DEFAULT_VERB];

	/* process the command line options. */
	while ((ch = getopt(argc, argv,
			    "D:R:r:N:n:i:M:u:p:t:b:k:J:V:T:"
			    "adfhIjmqSsUv468" QPARAM_GETOPT))
	       != -1)
	{
		switch (ch) {
		/* keep these in-sync with QPARAM_GETOPT. */
		case 'A': case 'B': case 'c':
		case 'g': case 'G':
		case 'l': case 'L':
		case 'O':
			if ((msg = qparam_option(ch, optarg, &qp)) != NULL)
				usage(msg);
			break;
		case 'a':
			asinfo_lookup = true;
			break;
		case 'D':
			asinfo_domain = optarg;
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
					qd.rrtype = strndup(p + 1, (size_t)
							    (q - p - 1));
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
					qd.rrtype = strndup(p + 1, (size_t)
							    (q - p - 1));
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
					qd.rrtype = strndup(p + 1, (size_t)
							    (q - p - 1));
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
					qd.rrtype = strndup(p + 1, (size_t)
							    (q - p - 1));
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
			if (!parse_long(optarg, &max_count) ||
			    (max_count <= 0))
				usage("-M must be positive");
			break;
		case 'u':
			picked_system = strdup(optarg);
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
				batching = batch_terse;
				break;
			case batch_terse:
				batching = batch_verbose;
				break;
			case batch_verbose:
				/* FALLTHROUGH */
			default:
				usage("too many -f options");
			}
			break;
		case 'T': {
			char *copy, *walker, *token;
			copy = walker = strdup(optarg);
			while ((token = strsep(&walker, ",")) != NULL)
				if (strcasecmp(token, "reverse") == 0)
					transforms |= TRANS_REVERSE;
				else if (strcasecmp(token, "datefix") == 0)
					transforms |= TRANS_DATEFIX;
				else if (strcasecmp(token, "chomp") == 0)
					transforms |= TRANS_CHOMP;
				else {
					DESTROY(copy);
					usage("unrecognized transform in -T");
				}
			DESTROY(copy);
			break;
		    }
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
		case '4':
			curl_ipresolve = CURL_IPRESOLVE_V4;
			break;
		case '6':
			curl_ipresolve = CURL_IPRESOLVE_V6;
			break;
		case '8':
			allow_8bit = true;
			break;
		default:
			usage("unrecognized option");
		}
	}
	argc -= optind;
	if (argc != 0)
		usage("there are no non-option arguments to this program");
	argv = NULL;

	if (allow_8bit == false && batching == batch_none &&
	    (qd.mode == name_mode || qd.mode == rrset_mode))
	{
		msg = check_7bit(qd.thing);
		if (msg != NULL)
			usage(msg);
	}

	if (asinfo_lookup) {
#ifdef CRIPPLED_LIBC
		usage("the -a option requires a modern functional C library.");
#else
		if (!asinfo_domain_exists(asinfo_domain)) {
			fprintf(stderr,
				"%s: ASINFO domain (%s) does not exist.\n",
				program_name, asinfo_domain);
			my_exit(1);
		}
#endif
	}

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
	if (config_file == NULL)
		config_file = select_config();
	if (picked_system != NULL) {
		psys_specified = true;
		pick_system(picked_system, "-u option");
		DESTROY(picked_system);
	} else {
		pick_system(DEFAULT_SYS, "default system");
		psys_specified = true;
	}

	if (json_fd != -1) {
#if WANT_PDNS_DNSDB
		/* the json output files are in COF format, never SAF. */
		if (strcmp(psys->name, "dnsdb2") == 0)
			pick_system("dnsdb1", "downgrade for -J");
#endif
		NULL;
	} else {
		make_curl();
		assert(psys_specified);
	}

	/* validate some interrelated options. */
	if (multiple && batching == batch_none)
		usage("using -m without -f makes no sense.");
	if ((msg = (*pverb->ok)()) != NULL)
		usage(msg);
	if ((msg = psys->verb_ok(pverb->name, &qp)) != NULL)
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
		if (qp.offset != 0)
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
		do_batch(stdin, &qp);
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
		if (psys->info == NULL)
			usage("there is no 'info' for this service");
		psys->info();
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

		writer_t writer = writer_init(qp.output_limit,
					      ps_stdout, false);
		(void) query_launcher(&qd, &qp, writer);
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
	}

	if (json_fd == -1) {
		unmake_curl();
	}

	/* clean up and go home. */
	DESTROY(qd.thing);
	DESTROY(qd.rrtype);
	DESTROY(qd.bailiwick);
	DESTROY(qd.pfxlen);
	my_exit(exit_code);
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
	DESTROY(config_file);
	if (psys != NULL)
		psys->destroy();

	/* sort key specifications and computations, are to be freed. */
	sort_destroy();

#ifndef CRIPPLED_LIBC
	/* asinfo logic has an internal DNS resolver context. */
	asinfo_shutdown();
#endif

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

/* Private. */

/* help -- display a brief usage-help text; then exit.
 *
 * this goes to stdout since we can expect it not to be piped unless to $PAGER.
 */
static void
help(void) {
	verb_ct v;

	printf("usage: %s [-acdfGghIjmqSsUv468] [-p dns|json|csv]\n",
	       program_name);
	puts("\t[-u SYSTEM] [-V VERB]\n"
	     "\t[-k (first|last|duration|count|name|data)[,...]]\n"
	     "\t[-l QUERY-LIMIT] [-L OUTPUT-LIMIT]\n"
	     "\t[-O OFFSET] [-M MAX_COUNT]\n"
	     "\t[-A AFTER] [-B BEFORE]\n"
	     "\t[-D ASINFO_DOMAIN] [-T (datefix,reverse,chomp)[,...] {\n"
	     "\t\t-f |\n"
	     "\t\t-J INPUTFILE |\n"
	     "\t\t[-t RRTYPE] [-b BAILIWICK] {\n"
	     "\t\t\t-r OWNER[/TYPE[/BAILIWICK]] |\n"
	     "\t\t\t-n NAME[/TYPE] |\n"
	     "\t\t\t-i IP[/PFXLEN] |\n"
	     "\t\t\t-N RAW-NAME-DATA[/TYPE]\n"
	     "\t\t\t-R RAW-OWNER-DATA[/TYPE[/BAILIWICK]]\n"
	     "\t\t}\n"
	     "\t}");
	printf("for -A and -B, use absolute format YYYY-MM-DD[ HH:MM:SS],\n"
	     "\tor relative format %%dw%%dd%%dh%%dm%%ds.\n"
	     "use -a to get ASNs associated with reported IP addresses\n"
	     "use -c to get complete (strict) time matching for -A and -B.\n"
	     "for -D, the default is \"%s\"\n"
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
	     "for -T, transforms are datefix, reverse, and chomp.\n"
	     "use -U to turn off SSL certificate verification.\n"
	     "use -v to show the program version.\n"
	     "use -4 to force connecting to the server via IPv4.\n"
	     "use -6 to force connecting to the server via IPv6.\n"
	     "use -8 to allow arbitrary 8-bit values in -r and -n arguments.\n",
	     asinfo_domain);

	puts("for -u, system must be one of:");
#if WANT_PDNS_DNSDB
	puts("\tdnsdb");
	puts("\tdnsdb2");
#endif
#if WANT_PDNS_CIRCL
	puts("\tcircl");
#endif
	puts("for -V, verb must be one of:");
	for (v = verbs; v->name != NULL; v++)
		printf("\t%s\n", v->name);
	puts("\nGetting Started:\n"
	     "\tAdd your API key to ~/.dnsdb-query.conf like this:\n"
	     "\t\tDNSDB_API_KEY=\"YOURAPIKEYHERE\"");
	printf("\nTry   man %s  for full documentation.\n", program_name);
}

/* qdesc_debug -- dump a qdesc.
 */
static void
qdesc_debug(const char *where, qdesc_ct qdp) {
	debug(true, "qdesc(%s)[", where);

	const char *sep = "\040";
	if (qdp->thing != NULL) {
		debug(false, "%sth '%s'", sep, qdp->thing);
		sep = ",\040";
	}
	if (qdp->rrtype != NULL) {
		debug(false, "%srr '%s'", sep, qdp->rrtype);
		sep = ",\040";
	}
	if (qdp->bailiwick != NULL) {
		debug(false, "%sbw '%s'", sep, qdp->bailiwick);
		sep = ",\040";
	}
	if (qdp->pfxlen != NULL) {
		debug(false, "%spfx '%s'", sep, qdp->pfxlen);
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

/* parse_long -- parse a base 10 long value.
 *
 * Return true if ok, else return false.
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
	if (qpp->complete && qpp->after != 0 && qpp->before != 0) {
		if (qpp->after > qpp->before)
			return "-A value must be before -B value"
			       " if using complete time matching";
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
		qpp->explicit_output_limit = qpp->output_limit;
		break;
	case 'O':
		if (!parse_long(optarg, &qpp->offset) ||
		    (qpp->offset < 0))
			return "-O must be zero or positive";
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
		return "max_count is not allowed for the lookup verb";
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

/* select_config -- try to find a config file in static path.
 */
static char *
select_config(void) {
	const char * const *conf;
	char *cf = NULL;

	for (conf = conf_files; *conf != NULL; conf++) {
		wordexp_t we;

		wordexp(*conf, &we, WRDE_NOCMD);
		cf = strdup(we.we_wordv[0]);
		wordfree(&we);
		if (access(cf, R_OK) == 0) {
			DEBUG(1, true, "conf found: '%s'\n", cf);
			return (cf);
		}
		DESTROY(cf);
	}
	return (NULL);
}

/* do_batch -- implement "filter" mode, reading commands from a batch file.
 */
static void
do_batch(FILE *f, qparam_ct qpp) {
	struct qparam qp = *qpp;
	writer_t writer = NULL;
	char *command = NULL;
	size_t n = 0;

	/* if doing multiple parallel upstreams, start a writer. */
	bool one_writer = multiple && batching != batch_verbose;
	if (one_writer)
		writer = writer_init(qp.output_limit, ps_stdout, false);

	while (getline(&command, &n, f) > 0) {
		const char *msg;
		struct qdesc qd;
		char *nl;

		/* the last line of the file may not have a newline. */
		nl = strchr(command, '\n');
		if (nl != NULL)
			*nl = '\0';

		/* allow # as a comment syntax */
		if (command[0] == '#')
			continue;

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
		if (!one_writer)
			writer = writer_init(qp.output_limit, ps_stdout, false);

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
			if (one_writer)
				io_engine(MAX_JOBS);
			else
				io_engine(0);
			if (query->status != NULL && batching != batch_verbose)
			{
				assert(query->message != NULL);
				fprintf(stderr,
					"%s: batch line status: %s (%s)\n",
					program_name,
					query->status, query->message);
			}
		}

		if (!one_writer) {
			/* think about showing the end-of-object separator.
			 * We reach here after all the queries from
			 * this batch line have finished.
			 */
			switch (batching) {
			case batch_none:
				break;
			case batch_terse:
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
	if (one_writer) {
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
	}
}

/* batch_options -- parse a $OPTIONS line out of a batch file.
 */
static const char *
batch_options(const char *optstr, qparam_t options, qparam_ct dflt) {
	char **optv = calloc(strlen(optstr) + 1, sizeof(char *));
	struct qparam save = *options;
	char **opt = optv;
	const char *msg;
	int optc, ch;
	char *tok;

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

	/* if no options were specified (e.g., $options\n), restore defaults.
	 */
	msg = NULL;
	optc = (int) (opt - optv);
	if (optc == 1) {
		DEBUG(2, true, "default options restored\n");
		*options = *dflt;
	} else {
		/* use getopt() to parse the cracked array. */
#if defined __GLIBC__
		/* glibc needs to have optind set to 0 instead of the
		 * "traditional value" of 1.
		 */
		optind = 0;
#else
		/* 1 is the value that optind should be initialized to,
		 * accorinng to IEEE Std 1003.1.
		 */
		optind = 1;
#if defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__ || \
	defined __APPLE__ || defined __DragonFly__
		/* BSD-like libc also needs to have optreset set to 1. */
		optreset = 1;
#endif /*BSD*/
#endif
		while ((ch = getopt(optc, optv, QPARAM_GETOPT)) != -1) {
			if ((msg = qparam_option(ch, optarg, options)) != NULL)
				break;
		}
		optc -= optind;
		if (msg == NULL && optc != 0)
			msg = "superfluous non-arguments in $OPTIONS";
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
	DESTROY(optv);
	DESTROY(temp);
	return msg;
}

/* batch_parse -- turn one line from a -f batch into a qdesc_t.
 */
static const char *
batch_parse(char *line, qdesc_t qdp) {
	struct qdesc qd = (struct qdesc) { };
	char *saveptr = NULL;
	const char *msg;
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
			if (allow_8bit == false &&
			    ((msg = check_7bit(t)) != NULL))
				return msg;
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
			if (allow_8bit == false &&
			    ((msg = check_7bit(t)) != NULL))
				return msg;
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
 *
 * Returns a string that must be free()d.
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
	struct pdns_fence fence = {};
	query_t query = NULL;

	CREATE(query, sizeof(struct query));
	query->writer = writer;
	writer = NULL;
	query->params = *qpp;
	query->next = query->writer->queries;
	query->writer->queries = query;
	query->command = makepath(qdp->mode, qdp->thing, qdp->rrtype,
				  qdp->bailiwick, qdp->pfxlen);

	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (qpp->after != 0) {
		if (qpp->complete) {
			/* each db tuple must begin after the fence-start. */
			fence.first_after = qpp->after;
		} else {
			/* each db tuple must end after the fence-start. */
			fence.last_after = qpp->after;
		}
	}
	if (qpp->before != 0) {
		if (qpp->complete) {
			/* each db tuple must end before the fence-end. */
			fence.last_before = qpp->before;
		} else {
			/* each db tuple must begin before the fence-end. */
			fence.first_before = qpp->before;
		}
	}
	launch(query, &fence);
	return query;
}

/* launch -- actually launch a query job, given a command and time fences.
 */
static void
launch(query_t query, pdns_fence_ct fp) {
	qparam_ct qpp = &query->params;
	char *url;

	url = psys->url(query->command, NULL, qpp, fp, false);
	if (url == NULL)
		my_exit(1);

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

	writer = writer_init(qpp->output_limit, NULL, false);
	CREATE(query, sizeof(struct query));
	query->writer = writer;
	query->params = *qpp;
	CREATE(fetch, sizeof(struct fetch));
	fetch->query = query;
	query->fetches = fetch;
	writer->queries = query;
	CREATE(buf, ideal_buffer);
	while ((len = read(json_fd, buf, ideal_buffer)) > 0) {
		writer_func(buf, 1, (size_t)len, query->fetches);
	}
	DESTROY(buf);
	writer_fini(writer);
	writer = NULL;
}

/* check_7bit -- check if its argument is 7 bit clean ASCII.
 *
 * returns NULL on success, else an error message.
 */
static const char *
check_7bit(const char *name) {
	int ch;

	while ((ch = *name++) != '\0')
		if ((ch & 0x80) != 0)
			return "search argument is not 7-bit clean";
	return NULL;
}
