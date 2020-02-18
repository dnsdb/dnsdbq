/*
 * Copyright (c) 2014-2018 by Farsight Security, Inc.
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
#include <sys/errno.h>

#include <assert.h>
#include <ctype.h>
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

extern char **environ;

/* Types. */

#define MAIN_PROGRAM 1
#include "defs.h"
#include "netio.h"
#include "pdns.h"
#include "pdns_dnsdb.h"
#include "pdns_circl.h"
#include "sort.h"
#include "time.h"
#include "globals.h"
#undef MAIN_PROGRAM

/* Forward. */

static void help(void);
static bool parse_long(const char *, long *);
static void server_setup(void);
static verb_ct find_verb(const char *);
static void read_configs(void);
static void do_batch(FILE *, u_long, u_long);
static const char *batch_parse(char *, query_t);
static char *makepath(mode_e, const char *, const char *,
		      const char *, const char *);
static void query_launcher(query_ct, writer_t);
static void launch(const char *, writer_t, u_long, u_long, u_long, u_long);
static void ruminate_json(int, u_long, u_long);
static void lookup_ready(void);
static void summarize_ready(void);

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
	{ "lookup", "/lookup", lookup_ready,
	  present_text_look, present_json, present_csv_look },
	{ "summarize", "/summarize", summarize_ready,
	  present_text_summ, present_json, present_csv_summ },
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Private. */

static enum { batch_none, batch_original, batch_verbose } batching = batch_none;
static bool merge = false;
static size_t ideal_buffer;

/* Public. */

int
main(int argc, char *argv[]) {
	mode_e mode = no_mode;
	char *thing = NULL, *rrtype = NULL, *bailiwick = NULL, *pfxlen = NULL;
	u_long after = 0;
	u_long before = 0;
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
	psys = pdns_dnsdb();

	/* process the command line options. */
	while ((ch = getopt(argc, argv,
			    "A:B:R:r:N:n:i:l:L:M:u:p:t:b:k:J:O:V:"
			    "cdfghIjmqSsUv"))

	       != -1)
	{
		switch (ch) {
		case 'A':
			if (!time_get(optarg, &after) || after == 0UL)
				usage("bad -A timestamp: '%s'\n", optarg);
			break;
		case 'B':
			if (!time_get(optarg, &before) || before == 0UL)
				usage("bad -B timestamp: '%s'\n", optarg);
			break;
		case 'R': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(thing == NULL);
			mode = raw_rrset_mode;

			p = strchr(optarg, '/');
			if (p != NULL) {
				if (rrtype != NULL || bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-R cannot contain a slash");

				const char *q;

				q = strchr(p + 1, '/');
				if (q != NULL) {
					bailiwick = strdup(q + 1);
					rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					rrtype = strdup(p + 1);
				}
				thing = strndup(optarg, (size_t)(p - optarg));
			} else {
				thing = strdup(optarg);
			}
			break;
		    }
		case 'r': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(thing == NULL);
			mode = rrset_mode;

			p = strchr(optarg, '/');
			if (p != NULL) {
				if (rrtype != NULL || bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-r cannot contain a slash");

				const char *q;

				q = strchr(p + 1, '/');
				if (q != NULL) {
					bailiwick = strdup(q + 1);
					rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					rrtype = strdup(p + 1);
				}
				thing = strndup(optarg, (size_t)(p - optarg));
			} else {
				thing = strdup(optarg);
			}
			break;
		    }
		case 'N': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(thing == NULL);
			mode = raw_name_mode;

			p = strchr(optarg, '/');
			if (p != NULL) {
				if (rrtype != NULL || bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-N cannot contain a slash");

				const char *q;

				q = strchr(p + 1, '/');
				if (q != NULL) {
					bailiwick = strdup(q + 1);
					rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					rrtype = strdup(p + 1);
				}
				thing = strndup(optarg, (size_t)(p - optarg));
			} else {
				thing = strdup(optarg);
			}
			break;
		    }
		case 'n': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(thing == NULL);
			mode = name_mode;

			p = strchr(optarg, '/');
			if (p != NULL) {
				if (rrtype != NULL || bailiwick != NULL)
					usage("if -b or -t are specified then "
					      "-n cannot contain a slash");

				const char *q;

				q = strchr(p + 1, '/');
				if (q != NULL) {
					bailiwick = strdup(q + 1);
					rrtype = strndup(p + 1,
							 (size_t)(q - p - 1));
				} else {
					rrtype = strdup(p + 1);
				}
				thing = strndup(optarg, (size_t)(p - optarg));
			} else {
				thing = strdup(optarg);
			}
			break;
		    }
		case 'i': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(thing == NULL);
			mode = ip_mode;
			p = strchr(optarg, '/');
			if (p != NULL) {
				thing = strndup(optarg, (size_t)(p - optarg));
				pfxlen = strdup(p + 1);
			} else {
				thing = strdup(optarg);
			}
			break;
		    }
		case 'V': {
			pverb = find_verb(optarg);
			if (pverb == NULL)
				usage("Unsupported verb for -V argument");
			break;
		    }
		case 'l':
			if (!parse_long(optarg, &query_limit) ||
			    (query_limit < 0))
				usage("-l must be zero or positive");
			break;
		case 'L':
			if (!parse_long(optarg, &output_limit) ||
			    (output_limit <= 0))
				usage("-L must be positive");
			break;
		case 'M':
			if (!parse_long(optarg, &max_count) || (max_count <= 0))
				usage("-M must be positive");
			break;
		case 'O':
			if (!parse_long(optarg, &offset) || (offset < 0))
				usage("-O must be zero or positive");
			break;
		case 'u':
			if (strcmp(optarg, "dnsdb") == 0)
				psys = pdns_dnsdb();
#if WANT_PDNS_CIRCL
			else if (strcmp(optarg, "circl") == 0)
				psys = pdns_circl();
#endif
			else
				usage("-u must refer to a pdns system");
			break;
		case 'U':
			donotverify = true;
			break;
		case 'p':
			if (strcasecmp(optarg, "json") == 0)
				presentation = json;
			else if (strcasecmp(optarg, "csv") == 0)
				presentation = csv;
			else if (strcasecmp(optarg, "text") == 0 ||
				 strcasecmp(optarg, "dns") == 0)
			{
				presentation = text;
			} else {
				usage("-p must specify json, text, or csv");
			}
			break;
		case 't':
			if (rrtype != NULL)
				usage("can only specify rrtype one way");
			rrtype = strdup(optarg);
			break;
		case 'b':
			if (bailiwick != NULL)
				usage("can only specify bailiwick one way");
			bailiwick = strdup(optarg);
			break;
		case 'k': {
			char *saveptr = NULL;
			const char *tok;

			if (sorted == no_sort)
				usage("-k must be preceded by -s or -S");
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
		case 'g':
			gravel = true;
			break;
		case 'j':
			presentation = json;
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
			merge = true;
			break;
		case 's':
			sorted = normal_sort;
			break;
		case 'S':
			sorted = reverse_sort;
			break;
		case 'c':
			complete = true;
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
	if (thing != NULL)
		escape(&thing);
	if (rrtype != NULL)
		escape(&rrtype);
	if (bailiwick != NULL)
		escape(&bailiwick);
	if (pfxlen != NULL)
		escape(&pfxlen);
	if (output_limit == -1 && query_limit != -1 && !merge)
		output_limit = query_limit;

	/* optionally dump program options as interpreted. */
	if (debug_level >= 1) {
		if (thing != NULL)
			debug(true, "thing = '%s'\n", thing);
		if (rrtype != NULL)
			debug(true, "type = '%s'\n", rrtype);
		if (bailiwick != NULL)
			debug(true, "bailiwick = '%s'\n", bailiwick);
		if (pfxlen != NULL)
			debug(true, "pfxlen = '%s'\n", pfxlen);
		if (after != 0)
			debug(true, "after = %ld : %s\n",
			      after, time_str(after, false));
		if (before != 0)
			debug(true, "before = %ld : ",
			      before, time_str(before, false));
		if (query_limit != -1)
			debug(true, "query_limit = %ld\n", query_limit);
		if (output_limit != -1)
			debug(true, "output_limit = %ld\n", output_limit);
		debug(true, "batching=%d, merge=%d\n",
		      batching != false, merge);
	}

	/* select presenter. */
	switch (presentation) {
	case text:
		presenter = pverb->text;
		break;
	case json:
		presenter = pverb->json;
		break;
	case csv:
		presenter = pverb->csv;
		break;
	default:
		abort();
	}

	/* validate some interrelated options. */
	if (after != 0 && before != 0) {
		if (after > 0 && before > 0 && after > before)
			usage("-A -B requiress after <= before (for now)");
		if (sorted == no_sort && json_fd == -1 &&
		    !complete && !quiet)
		{
			fprintf(stderr,
				"%s: warning: -A and -B w/o -c needs"
				" sort for dedup; turning on -S here.\n",
				program_name);
			sorted = reverse_sort;
		}
	}
	if (complete && !after && !before)
		usage("-c without -A or -B makes no sense.");
	if (merge) {
		switch (batching) {
		case batch_none:
			usage("using -m without -f makes no sense.");
		case batch_original:
			break;
		case batch_verbose:
			usage("using -m with more than one -f makes no sense.");
		}
	}

	if (sorted != no_sort)
		sort_ready();
	(*pverb->ready)();
	if ((msg = psys->verb_ok(pverb->name)) != NULL)
		usage(msg);

	/* get some input from somewhere, and use it to drive our output. */
	if (json_fd != -1) {
		if (mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -J");
		if (batching != batch_none)
			usage("can't mix -f with -J");
		if (bailiwick != NULL)
			usage("can't mix -b with -J");
		if (info)
			usage("can't mix -I with -J");
		if (rrtype != NULL)
			usage("can't mix -t with -J");
		if (pverb != &verbs[DEFAULT_VERB])
			usage("can't mix -V with -J");
		if (max_count > 0)
			usage("can't mix -M with -J");
		if (gravel)
			usage("can't mix -g with -J");
		if (offset != 0)
			usage("can't mix -O with -J");
		ruminate_json(json_fd, after, before);
		close(json_fd);
	} else if (batching != batch_none) {
		if (mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -f");
		if (bailiwick != NULL)
			usage("can't mix -b with -f");
		if (rrtype != NULL)
			usage("can't mix -t with -f");
		if (info)
			usage("can't mix -I with -f");
		server_setup();
		make_curl();
		do_batch(stdin, after, before);
		unmake_curl();
	} else if (info) {
		if (mode != no_mode)
			usage("can't mix -n, -r, -i, or -R with -I");
		if (presentation != text && presentation != json)
			usage("info must be presented in json or text format");
		if (bailiwick != NULL)
			usage("can't mix -b with -I");
		if (rrtype != NULL)
			usage("can't mix -t with -I");
		if (psys->request_info == NULL || psys->info_blob == NULL)
			usage("there is no 'info' for this service");
		server_setup();
		make_curl();
		psys->request_info();
		unmake_curl();
	} else {
		writer_t writer;
		struct query q;

		if (mode == no_mode)
			usage("must specify -r, -n, -i, or -R"
			      " unless -f or -J is used");
		if (bailiwick != NULL) {
			if (mode == ip_mode)
				usage("can't mix -b with -i");
			if (mode == raw_rrset_mode)
				usage("can't mix -b with -R");
			if (mode == raw_name_mode)
				usage("can't mix -b with -N");
			if (mode == name_mode)
				usage("can't mix -b with -n");
		}
		if (mode == ip_mode && rrtype != NULL)
			usage("can't mix -i with -t");

		q = (struct query) {
			.mode = mode,
			.thing = thing,
			.rrtype = rrtype,
			.bailiwick = bailiwick,
			.pfxlen = pfxlen,
			.after = after,
			.before = before
		};
		server_setup();
		make_curl();
		writer = writer_init(q.after, q.before);
		query_launcher(&q, writer);
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
		unmake_curl();
	}

	/* clean up and go. */
	DESTROY(thing);
	DESTROY(rrtype);
	DESTROY(bailiwick);
	DESTROY(pfxlen);
	my_exit(exit_code);
}

/* Private. */

/* help -- display a brief usage-help text; then exit.
 *
 * this goes to stdout since we can expect it not to be piped unless to $PAGER.
 */
static void
help(void) {
	verb_ct v;

	printf("usage: %s [-cdfghIjmqSsUv] [-p dns|json|csv]\n", program_name);
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
	     "\t  rrset/name/NAME[/TYPE[/BAILIWICK]]\n"
	     "\t  rrset/raw/HEX-PAIRS[/RRTYPE[/BAILIWICK]]\n"
	     "\t  rdata/name/NAME[/TYPE]\n"
	     "\t  rdata/ip/ADDR[,PFXLEN]\n"
	     "\t  rdata/raw/HEX-PAIRS[/RRTYPE]\n"
	     "\t  (output format will be determined by -p, "
	     "using --\\n framing.\n"
	     "use -g to get graveled results.\n"
	     "use -h to reliably display this helpful text.\n"
	     "use -I to see a system-specific account/key summary.\n"
	     "for -J, input format is newline-separated JSON, "
	     "as from -j output.\n"
	     "use -j as a synonym for -p json.\n"
	     "use -M # to end a summarize op when count exceeds threshold.\n"
	     "use -m with -f to merge all answers into a single result.\n"
	     "use -O # to skip this many results in what is returned.\n"
	     "use -q for warning reticence.\n"
	     "use -s to sort in ascending order, "
	     "or -S for descending order.\n"
	     "\t-s/-S can be repeated before several -k arguments.\n"
	     "use -U to turn off SSL certificate verification.\n"
	     "use -v to show the program version.");
	puts("for -u, system must be one of:");
	puts("\tdnsdb\n");
#if WANT_PDNS_CIRCL
	puts("\tcircl\n");
#endif
	puts("for -V, verb must be one of:");
	for (v = verbs; v->name != NULL; v++)
		printf("\t%s\n", v->name);
	puts("\nGetting Started:\n"
	     "\tAdd your API key to ~/.dnsdb-query.conf like this:\n"
	     "\t\tAPIKEY=\"YOURAPIKEYHERE\"");
	printf("\nTry   man %s  for full documentation.\n", program_name);
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

/* usage -- display a usage error message, brief usage help text; then exit.
 *
 * this goes to stderr in case stdout has been piped or redirected.
 */
__attribute__((noreturn)) void
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

/* my_exit -- close or destroy global objects, then exit.
 */
__attribute__((noreturn)) void
my_exit(int code) {
	/* writers and readers which are still known, must be freed. */
	unmake_writers();

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	/* globals which may have been initialized, are to be freed. */
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

/* parse a base 10 long value.	Return true if ok, else return false.
 */
static bool
parse_long(const char *in, long *out) {
	char *ep;
	long result = strtol(in, &ep, 10);

	if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) ||
	    (errno != 0 && result == 0) ||
	    (ep == in))
		return false;
	*out = result;
	return true;
}

/* validate_cmd_opts_lookup -- validate command line options for 'lookup'.
 */
static void
lookup_ready(void) {
	/* TODO too many local variables would need to be global to check
	 * more here.
	 */
	if (max_count > 0)
		usage("max_count only allowed for a summarize verb");
}

/* validate_cmd_opts_summarize -- validate commandline options for 'summarize'.
 */
static void
summarize_ready(void) {
	if (sorted != no_sort)
		usage("Sorting with a summarize verb makes no sense");
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

/* server_setup -- learn the server name and API key by various means.
 */
static void
server_setup(void) {
	read_configs();
	psys->ready();
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
			     "echo dnsdb apikey $APIKEY;"
			     "echo dnsdn server $DNSDB_SERVER;"
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
			if (strcmp(tok1, psys->name) != 0 ||
			    tok3 == NULL || *tok3 == '\0')
				continue;

			DEBUG(1, true, "line #%d: sets %s|%s|%s\n",
			      l, tok1, tok2, tok3);
			if ((msg = psys->setenv(tok2, tok3)) != NULL)
				usage(msg);
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
do_batch(FILE *f, u_long after, u_long before) {
	writer_t writer = NULL;
	char *command = NULL;
	size_t n = 0;

	/* if merging, start a writer. */
	if (merge)
		writer = writer_init(after, before);

	while (getline(&command, &n, f) > 0) {
		const char *msg;
		struct query q;
		char *nl;

		/* the last line of the file may not have a newline. */
		nl = strchr(command, '\n');
		if (nl != NULL)
			*nl = '\0';
		
		DEBUG(1, true, "do_batch(%s)\n", command);

		/* if not merging, start a writer here instead. */
		if (!merge) {
			writer = writer_init(after, before);
			/* only verbose batching shows query startups. */
			if (batching == batch_verbose)
				fprintf(stdout, "++ %s\n", command);
		}

		/* crack the batch line if possible. */
		msg = batch_parse(command, &q);
		if (msg != NULL) {
			writer_status(writer, "PARSE", msg);
		} else {
			/* manage batch-level defaults as -A and -B. */
			if (q.after == 0)
				q.after = after;
			if (q.before == 0)
				q.before = before;

			/* start one or two curl jobs based on this search. */
			query_launcher((query_ct)&q, writer);

			/* if merging, drain some jobs; else, drain all jobs. */
			if (merge) {
				io_engine(MAX_JOBS);
			} else {
				io_engine(0);
			}
		}
		if (writer->status != NULL && batching != batch_verbose) {
			assert(writer->message != NULL);
			fprintf(stderr, "%s: batch line status: %s (%s)\n",
				program_name, writer->status, writer->message);
		}

		/* think about showing the end-of-object separator. */
		if (!merge) {
			switch (batching) {
			case batch_none:
				break;
			case batch_original:
				fprintf(stdout, "--\n");
				break;
			case batch_verbose:
				fprintf(stdout, "-- %s (%s)\n",
					or_else(writer->status, "NOERROR"),
					or_else(writer->message, "no error"));
				break;
			default:
				abort();
			}
			fflush(stdout);
			writer_fini(writer);
			writer = NULL;
		}
	}
	DESTROY(command);
	
	/* if merging, run remaining jobs to completion, then finish up. */
	if (merge) {
		io_engine(0);
		writer_fini(writer);
		writer = NULL;
	}
}

/* batch_parse -- turn one line from a -f batch into a (struct query).
 */
static const char *
batch_parse(char *line, query_t qp) {
	struct query q = (struct query) { };
	char *saveptr = NULL;
	char *t;
	
	if ((t = strtok_r(line, "/", &saveptr)) == NULL)
		return "too few terms";
	if (strcmp(t, "rrset") == 0) {
		if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
			return "missing term after 'rrset/'";
		if (strcmp(t, "name") == 0) {
			q.mode = rrset_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rrset/name/'";
			q.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				q.rrtype = t;
				if ((t = strtok_r(NULL, "/", &saveptr))
				    != NULL)
				{
					q.bailiwick = t;
				}
			}
		} else if (strcmp(t, "raw") == 0) {
			q.mode = raw_rrset_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rrset/raw/'";
			q.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				q.rrtype = t;
				if ((t = strtok_r(NULL, "/", &saveptr))
				    != NULL)
				{
					q.bailiwick = t;
				}
			}
		} else {
			return "unrecognized term after 'rrset/'";
		}
	} else if (strcmp(t, "rdata") == 0) {
		if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
			return "missing term after 'rdata/'";
		if (strcmp(t, "name") == 0) {
			q.mode = name_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/name/'";
			q.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				q.rrtype = t;
			}
		} else if (strcmp(t, "raw") == 0) {
			q.mode = raw_name_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/raw/'";
			q.thing = t;
			if ((t = strtok_r(NULL, "/", &saveptr)) != NULL) {
				q.rrtype = t;
			}
		} else if (strcmp(t, "ip") == 0) {
			q.mode = ip_mode;
			if ((t = strtok_r(NULL, "/", &saveptr)) == NULL)
				return "missing term after 'rdata/ip/'";
			q.thing = t;
		} else {
			return "unrecognized term after 'rdata/'";
		}
	} else {
		return "unrecognized initial term";
	}
	t = strtok_r(NULL, "/", &saveptr);
	if (t != NULL)
		return "extra garbage";
	*qp = q;
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
static void
query_launcher(query_ct qp, writer_t writer) {
	char *command;
	
	command = makepath(qp->mode, qp->thing, qp->rrtype,
			   qp->bailiwick, qp->pfxlen);

	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (qp->after != 0 && qp->before != 0) {
		if (complete) {
			/* each db tuple must be enveloped by time fence. */
			launch(command, writer, qp->after, 0, 0, qp->before);
		} else {
			/* we need tuples that end after fence start... */
			launch(command, writer, 0, 0, qp->after, 0);
			/* ...and that begin before the time fence end. */
			launch(command, writer, 0, qp->before, 0, 0);
			/* and we will filter in reader_func() to
			 * select only those tuples which either:
			 * ...(start within), or (end within), or
			 * ...(start before and end after).
			 */
		}
	} else if (qp->after != 0) {
		if (complete) {
			/* each db tuple must begin after the fence-start. */
			launch(command, writer, qp->after, 0, 0, 0);
		} else {
			/* each db tuple must end after the fence-start. */
			launch(command, writer, 0, 0, qp->after, 0);
		}
	} else if (qp->before != 0) {
		if (complete) {
			/* each db tuple must end before the fence-end. */
			launch(command, writer, 0, 0, 0, qp->before);
		} else {
			/* each db tuple must begin before the fence-end. */
			launch(command, writer, 0, qp->before, 0, 0);
		}
	} else {
		/* no time fencing. */
		launch(command, writer, 0, 0, 0, 0);
	}
	DESTROY(command);
}

/* launch -- actually launch a query job, given a command and time fences.
 */
static void
launch(const char *command, writer_t writer,
       u_long first_after, u_long first_before,
       u_long last_after, u_long last_before)
{
	char *url, *tmp, sep;
	int x;

	url = psys->url(command, &sep);
	if (url == NULL)
		my_exit(1);

	if (query_limit != -1) {
		x = asprintf(&tmp, "%s%c" "limit=%ld", url, sep, query_limit);
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

	reader_launch(writer, url);
}

/* ruminate_json -- process a json file from the filesys rather than the API.
 */
static void
ruminate_json(int json_fd, u_long after, u_long before) {
	reader_t reader = NULL;
	void *buf = NULL;
	writer_t writer;
	ssize_t len;

	writer = writer_init(after, before);
	CREATE(reader, sizeof(struct reader));
	reader->writer = writer;
	writer->readers = reader;
	reader = NULL;
	CREATE(buf, ideal_buffer);
	while ((len = read(json_fd, buf, sizeof buf)) > 0) {
		writer_func(buf, 1, (size_t)len, writer->readers);
	}
	DESTROY(buf);
	writer_fini(writer);
	writer = NULL;
}

