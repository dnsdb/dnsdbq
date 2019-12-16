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

/* optional features. */
#define WANT_PDNS_CIRCL 1

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/errno.h>

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <jansson.h>
#include "ns_ttl.h"

extern char **environ;

/* Types. */

/* conforms to the fields in the IETF passive DNS COF draft
 * except for num_results which is an addition for summarize.
 */
struct pdns_json {
	json_t	*main,
		*time_first, *time_last, *zone_first, *zone_last,
		*bailiwick, *rrname, *rrtype, *rdata,
		*count, *num_results;
};

struct pdns_tuple {
	struct pdns_json  obj;
	u_long		  time_first, time_last, zone_first, zone_last;
	const char	 *bailiwick, *rrname, *rrtype, *rdata;
	json_int_t	  count, num_results;
};
typedef struct pdns_tuple *pdns_tuple_t;
typedef const struct pdns_tuple *pdns_tuple_ct;

/* presentation formatter function for a passive DNS tuple */
typedef void (*present_t)(pdns_tuple_ct, const char *, size_t, FILE *);

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

struct reader {
	struct reader	*next;
	struct writer	*writer;
	CURL		*easy;
	struct curl_slist  *hdrs;
	char		*url;
	char		*buf;
	size_t		len;
	long		rcode;
};
typedef struct reader *reader_t;

struct writer {
	struct writer	*next;
	struct reader	*readers;
	u_long		after;
	u_long		before;
	FILE		*sort_stdin;
	FILE		*sort_stdout;
	pid_t		sort_pid;
	bool		sort_killed;
	int		count;
	char		*status;
	char		*message;
	bool		once;
};
typedef struct writer *writer_t;

struct verb {
	const char	*cmd_opt_val;
	const char	*url_fragment;
	/* validate_cmd_opts can review the command line options and exit
	 * if some verb-specific command line option constraint is not met.
	 */
	void		(*validate_cmd_opts)(void);
};
typedef const struct verb *verb_t;

struct pdns_sys {
	const char	*name;
	const char	*base_url;
	/* first argument is the input URL path.
	 * second is an output parameter pointing to
	 * the separator character (? or &) that the caller should
	 * use between any further URL parameters.  May be
	 * NULL if the caller doesn't care.
	 */
	char *		(*url)(const char *, char *);
	void		(*request_info)(void);
	void		(*write_info)(reader_t);
	void		(*auth)(reader_t);
	const char *	(*status)(reader_t);
	bool		(*validate_verb)(const char *verb);
};
typedef const struct pdns_sys *pdns_sys_t;

typedef enum { no_mode = 0, rrset_mode, name_mode, ip_mode,
	       raw_rrset_mode, raw_name_mode } mode_e;

struct sortbuf { char *base; size_t size; };
typedef struct sortbuf *sortbuf_t;

struct sortkey { char *specified, *computed; };
typedef struct sortkey *sortkey_t;
typedef const struct sortkey *sortkey_ct;

/* DNSDB specific Types. */

struct dnsdb_rate_json {
	json_t	*main,
		*reset, *expires, *limit, *remaining,
		*burst_size, *burst_window, *results_max,
		*offset_max;
};

struct dnsdb_rate_tuple {
	struct dnsdb_rate_json	obj;
	struct rateval	reset, expires, limit, remaining,
			burst_size, burst_window, results_max,
			offset_max;
};
typedef struct dnsdb_rate_tuple *dnsdb_rate_tuple_t;


/* Forward. */

static void help(void);
static bool parse_long(const char *, long *);
static void report_version(void);
static __attribute__((noreturn)) void usage(const char *);
static __attribute__((noreturn)) void my_exit(int, ...);
static __attribute__((noreturn)) void my_panic(const char *);
static void server_setup(void);
static const char *add_sort_key(const char *);
static sortkey_ct find_sort_key(const char *);
static pdns_sys_t find_system(const char *);
static verb_t find_verb(const char *);
static void read_configs(void);
static void read_environ(void);
static void do_batch(FILE *, u_long, u_long);
static char *makepath(mode_e, const char *, const char *,
		      const char *, const char *);
static void make_curl(void);
static void unmake_curl(void);
static void pdns_query(const char *, u_long, u_long);
static void query_launcher(const char *, writer_t, u_long, u_long);
static void launch(const char *, writer_t, u_long, u_long, u_long, u_long);
static void launch_one(writer_t, char *);
static void rendezvous(reader_t);
static void ruminate_json(int, u_long, u_long);
static writer_t writer_init(u_long, u_long);
static size_t writer_func(char *ptr, size_t size, size_t nmemb, void *blob);
static int input_blob(const char *, size_t, u_long, u_long, FILE *);
static void writer_fini(writer_t);
static void io_engine(int);
static void present_text(pdns_tuple_ct, const char *, size_t, FILE *);
static void present_json(pdns_tuple_ct, const char *, size_t, FILE *);
static void present_csv(pdns_tuple_ct, const char *, size_t, FILE *);
static void present_csv_line(pdns_tuple_ct, const char *, FILE *);
static void present_text_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
static void present_json_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
static void present_csv_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
static const char *tuple_make(pdns_tuple_t, const char *, size_t);
static void print_rateval(const char *, rateval_ct, FILE *);
static void print_burstrate(const char *, rateval_ct, rateval_ct, FILE *);
static const char *rateval_make(rateval_t, const json_t *, const char *);
static void tuple_unmake(pdns_tuple_t);
static int timecmp(u_long, u_long);
static void time_print(u_long x, FILE *);
static int time_get(const char *src, u_long *dst);
static void escape(char **);
static char *sortable_rrname(pdns_tuple_ct);
static char *sortable_rdata(pdns_tuple_ct);
static void sortable_rdatum(sortbuf_t, const char *, const char *);
static void sortable_dnsname(sortbuf_t, const char *);
static void sortable_hexify(sortbuf_t, const u_char *, size_t);
static void validate_cmd_opts_lookup(void);
static void validate_cmd_opts_summarize(void);
static const char *or_else(const char *, const char *);

/* DNSDB specific Forward. */

static const char *dnsdb_rate_tuple_make(dnsdb_rate_tuple_t, const char *,
					 size_t);
static void dnsdb_rate_tuple_unmake(dnsdb_rate_tuple_t);
static char *dnsdb_url(const char *, char *);
static void dnsdb_request_info(void);
static void dnsdb_write_info(reader_t);
static void dnsdb_auth(reader_t);
static const char *dnsdb_status(reader_t);
static bool dnsdb_validate_verb(const char*);

#if WANT_PDNS_CIRCL
/* CIRCL specific Forward. */

static char *circl_url(const char *, char *);
static void circl_auth(reader_t);
static const char *circl_status(reader_t);
static bool circl_validate_verb(const char*);
#endif

/* Constants. */

static const char * const conf_files[] = {
	"~/.isc-dnsdb-query.conf",
	"~/.dnsdb-query.conf",
	"/etc/isc-dnsdb-query.conf",
	"/etc/dnsdb-query.conf",
	NULL
};

static const char path_sort[] = "/usr/bin/sort";
static const char json_header[] = "Accept: application/json";
static const char env_api_key[] = "DNSDB_API_KEY";
static const char env_dnsdb_base_url[] = "DNSDB_SERVER";
static const char env_time_fmt[] = "DNSDB_TIME_FORMAT";

/* We pass swclient=$id_swclient&version=$id_version in all queries to DNSDB. */
static const char id_swclient[] = "dnsdbq";
static const char id_version[] = "1.4";

static const struct pdns_sys pdns_systems[] = {
	/* note: element [0] of this array is the default. */
	{ "dnsdb", "https://api.dnsdb.info",
	  dnsdb_url, dnsdb_request_info, dnsdb_write_info,
	  dnsdb_auth, dnsdb_status, dnsdb_validate_verb },
#if WANT_PDNS_CIRCL
	{ "circl", "https://www.circl.lu/pdns/query",
	  circl_url, NULL, NULL,
	  circl_auth, circl_status, circl_validate_verb },
#endif
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

static const struct verb verbs[] = {
	/* note: element [0] of this array is the default. */
	{ "lookup", "/lookup", validate_cmd_opts_lookup },
	{ "summarize", "/summarize", validate_cmd_opts_summarize },
	{ NULL, NULL, NULL }
};

#define	MAX_KEYS 5
#define	MAX_JOBS 8

#define CREATE(p, s) if ((p) != NULL) { my_panic("non-NULL ptr"); }	\
	else if (((p) = malloc(s)) == NULL) { my_panic("malloc failed"); } \
	else { memset((p), 0, s); }
#define DESTROY(p) { if ((p) != NULL) { free(p); (p) = NULL; } }

/* Private. */

static const char *program_name = NULL;
static char *api_key = NULL;
static verb_t chosen_verb = &verbs[0];
static char *dnsdb_base_url = NULL;
#if WANT_PDNS_CIRCL
static char *circl_base_url = NULL;
static char *circl_authinfo = NULL;
#endif
static pdns_sys_t sys = pdns_systems;
static enum { batch_none, batch_original, batch_verbose } batching = batch_none;
static bool merge = false;
static bool complete = false;
static bool info = false;
static bool gravel = false;
static bool quiet = false;
static int debuglev = 0;
static enum { no_sort = 0, normal_sort, reverse_sort } sorted = no_sort;
static int curl_cleanup_needed = 0;
static present_t pres = present_text;
static int query_limit = -1;	/* -1 means not set on command line. */
static int output_limit = -1;	/* -1 means not set on command line. */
static long offset = 0;
static long max_count = 0;
static CURLM *multi = NULL;
static struct timeval now;
static int nkeys = 0;
static struct sortkey keys[MAX_KEYS];
static bool sort_byname = false;
static bool sort_bydata = false;
static writer_t writers = NULL;
static int exit_code = 0; /* hopeful */
static size_t ideal_buffer;

/* Public. */

int
main(int argc, char *argv[]) {
	mode_e mode = no_mode;
	char *name = NULL, *rrtype = NULL, *bailiwick = NULL,
		*prefix_length = NULL;
	u_long after = 0;
	u_long before = 0;
	int json_fd = -1;
	int ch;

	/* global dynamic initialization. */
	ideal_buffer = 4 * (size_t) sysconf(_SC_PAGESIZE);
	gettimeofday(&now, NULL);
	program_name = strrchr(argv[0], '/');
	if (program_name != NULL)
		program_name++;
	else
		program_name = argv[0];

	/* process the command line options. */
	while ((ch = getopt(argc, argv,
			    "A:B:R:r:N:n:i:l:L:M:u:p:t:b:k:J:O:V:djfmsShcIgqv"))
	       != -1)
	{
		switch (ch) {
		case 'A':
			if (!time_get(optarg, &after)) {
				fprintf(stderr, "bad -A timestamp: '%s'\n",
					optarg);
				my_exit(1, NULL);
			}
			break;
		case 'B':
			if (!time_get(optarg, &before)) {
				fprintf(stderr, "bad -B timestamp: '%s'\n",
					optarg);
				my_exit(1, NULL);
			}
			break;
		case 'R': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(name == NULL);
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
				name = strndup(optarg, (size_t)(p - optarg));
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'r': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(name == NULL);
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
				name = strndup(optarg, (size_t)(p - optarg));
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'N': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(name == NULL);
			mode = raw_name_mode;

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
				name = strndup(optarg, (size_t)(p - optarg));
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'n': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(name == NULL);
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
				name = strndup(optarg, (size_t)(p - optarg));
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'i': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, -i, -N, or -R "
				      "can only appear once");
			assert(name == NULL);
			mode = ip_mode;
			p = strchr(optarg, '/');
			if (p != NULL) {
				name = strndup(optarg, (size_t)(p - optarg));
				prefix_length = strdup(p + 1);
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'V': {
			chosen_verb = find_verb(optarg);
			if (chosen_verb == NULL)
				usage("Unsupported verb for -V argument");
			break;
		    }
		case 'l':
			query_limit = atoi(optarg);
			if (query_limit < 0)
				usage("-l must be zero or positive");
			break;
		case 'L':
			output_limit = atoi(optarg);
			if (output_limit <= 0)
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
			sys = find_system(optarg);
			if (sys == NULL)
				usage("-u must refer to a pdns system");
			break;
		case 'p':
			if (strcasecmp(optarg, "json") == 0)
				pres = present_json;
			else if (strcasecmp(optarg, "csv") == 0)
				pres = present_csv;
			else if (strcasecmp(optarg, "text") == 0 ||
				 strcasecmp(optarg, "dns") == 0)
			{
				pres = present_text;
			} else {
				usage("-p must specify json, text, or csv");
			}
			break;
		case 't':
			if (rrtype != NULL)
				usage("can only specify rrtype one way");
			if (mode != no_mode && mode != ip_mode)
				fprintf(stderr,
					"Warning: -t option should be before "
					"the -R, -r, or -n options\n");
			rrtype = strdup(optarg);
			break;
		case 'b':
			if (bailiwick != NULL)
				usage("can only specify bailiwick one way");
			bailiwick = strdup(optarg);
			break;
		case 'k': {
			const char *tok;
			if (nkeys > 0)
				usage("Can only specify -k once; use commas "
				      "to separate multiple sort fields");

			nkeys = 0;
			for (tok = strtok(optarg, ",");
			     tok != NULL;
			     tok = strtok(NULL, ","))
			{
				const char *msg;

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
				my_panic(optarg);
			break;
		case 'd':
			debuglev++;
			break;
		case 'g':
			gravel = true;
			break;
		case 'j':
			pres = present_json;
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
			report_version();
			my_exit(0, NULL);
		case 'q':
			quiet = true;
			break;
		case 'h':
			help();
			my_exit(0, NULL);
		default:
			usage("unrecognized option");
		}
	}
	argc -= optind;
	if (argc != 0)
		usage("there are no non-option arguments to this program");
	argv = NULL;

	/* recondition various options for HTML use. */
	if (name != NULL)
		escape(&name);
	if (rrtype != NULL)
		escape(&rrtype);
	if (bailiwick != NULL)
		escape(&bailiwick);
	if (prefix_length != NULL)
		escape(&prefix_length);
	if (output_limit == -1 && query_limit != -1 && !merge)
		output_limit = query_limit;

	/* optionally dump program options as interpreted. */
	if (debuglev > 0) {
		if (name != NULL)
			fprintf(stderr, "name = '%s'\n", name);
		if (rrtype != NULL)
			fprintf(stderr, "type = '%s'\n", rrtype);
		if (bailiwick != NULL)
			fprintf(stderr, "bailiwick = '%s'\n", bailiwick);
		if (prefix_length != NULL)
			fprintf(stderr, "prefix_length = '%s'\n",
				prefix_length);
		if (after != 0) {
			fprintf(stderr, "after = %ld : ", (long)after);
			time_print(after, stderr);
			putc('\n', stderr);
		}
		if (before != 0) {
			fprintf(stderr, "before = %ld : ", (long)before);
			time_print(before, stderr);
			putc('\n', stderr);
		}
		if (query_limit != -1)
			fprintf(stderr, "query_limit = %d\n", query_limit);
		if (output_limit != -1)
			fprintf(stderr, "output_limit = %d\n", output_limit);
		fprintf(stderr, "batching=%d, merge=%d\n",
			(int)batching, merge);
	}

	/* validate some interrelated options. */
	if (after != 0 && before != 0) {
		if (after > 0 && before > 0 && after > before)
			usage("-A -B requires after <= before (for now)");
		if (sorted == no_sort && json_fd == -1 && !complete) {
			fprintf(stderr,
				"-A and -B w/o -c requires sorting for dedup, "
				"so turning on -S here.\n");
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
	if (nkeys > 0 && sorted == no_sort)
		usage("using -k without -s or -S makes no sense.");
	if (nkeys < MAX_KEYS && sorted != no_sort) {
		/* if sorting, all keys must be specified, to enable -u. */
		if (find_sort_key("first") == NULL)
			(void) add_sort_key("first");
		if (find_sort_key("last") == NULL)
			(void) add_sort_key("last");
		if (find_sort_key("count") == NULL)
			(void) add_sort_key("count");
		if (find_sort_key("name") == NULL)
			(void) add_sort_key("name");
		if (find_sort_key("data") == NULL)
			(void) add_sort_key("data");
	}

	assert(chosen_verb != NULL);
	if (chosen_verb->validate_cmd_opts != NULL)
		(*chosen_verb->validate_cmd_opts)();
	if (sys->validate_verb != NULL)
		if (sys->validate_verb(chosen_verb->cmd_opt_val) == false)
			usage("That verb is not supported by that system");

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
		if (pres != present_text && pres != present_json)
			usage("info must be presented in json or text format");
		if (bailiwick != NULL)
			usage("can't mix -b with -I");
		if (rrtype != NULL)
			usage("can't mix -t with -I");
		if (sys->request_info == NULL || sys->write_info == NULL)
			usage("there is no 'info' for this service");
		server_setup();
		make_curl();
		sys->request_info();
		unmake_curl();
	} else {
		char *command;

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

		command = makepath(mode, name, rrtype, bailiwick,
				   prefix_length);
		server_setup();
		make_curl();
		pdns_query(command, after, before);
		DESTROY(command);
		unmake_curl();
	}

	/* clean up and go. */
	DESTROY(name);
	DESTROY(rrtype);
	DESTROY(bailiwick);
	DESTROY(prefix_length);
	my_exit(exit_code, NULL);
}

/* Private. */

/* help -- display a brief usage-help text; then exit.
 */
static void
help(void) {
	pdns_sys_t t;
	verb_t v;

	fprintf(stderr,
		"usage: %s [-djsShcIgqv] [-p dns|json|csv]\n"
		"\t[-k (first|last|count|name|data)[,...]]\n"
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
		"\t}\n",
		program_name);
	fprintf(stderr,
		"for -A and -B, use abs. YYYY-MM-DD[ HH:MM:SS] "
		"or rel. %%dw%%dd%%dh%%dm%%ds format.\n"
		"use -c to get complete (strict) time matching for -A and -B.\n"
		"use -d one or more times to ramp up the diagnostic output.\n"
		"for -f, stdin must contain lines of the following forms:\n"
		"\t  rrset/name/NAME[/TYPE[/BAILIWICK]]\n"
		"\t  rrset/raw/HEX-PAIRS[/RRTYPE[/BAILIWICK]]\n"
		"\t  rdata/name/NAME[/TYPE]\n"
		"\t  rdata/ip/ADDR[/PFXLEN]\n"
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
		"use -O # to skip this many results in what is returned.\n"
		"use -q for warning reticence.\n"
		"use -v to show the program version.\n"
		"use -s to sort in ascending order, "
		"or -S for descending order.\n");
	fprintf(stderr, "for -u, system must be one of:\n");
	for (t = pdns_systems; t->name != NULL; t++)
		fprintf(stderr, "\t%s\n", t->name);
	fprintf(stderr, "for -V, verb must be one of:\n");
	for (v = verbs; v->cmd_opt_val != NULL; v++)
		fprintf(stderr, "\t%s\n", v->cmd_opt_val);
	fprintf(stderr,
		"\nGetting Started:\n"
		"\tAdd your API key to ~/.dnsdb-query.conf like this:\n"
		"\t\tAPIKEY=\"YOURAPIKEYHERE\"\n");
	fprintf(stderr, "\nTry   man %s  for full documentation.\n",
		program_name);
}

static void
report_version(void) {
	fprintf(stderr, "%s: %s version %s\n",
		program_name, id_swclient, id_version);
}

/* usage -- display a usage error message, brief usage help text; then exit.
 */
static __attribute__((noreturn)) void
usage(const char *error) {
	fprintf(stderr,
		"error: %s\n"
		"\n"
		"try   %s -h   for a short description of program usage.\n",
		error, program_name);
	my_exit(1, NULL);
}

/* my_exit -- free all known heap objects, then exit.
 */
static __attribute__((noreturn)) void
my_exit(int code, ...) {
	va_list ap;
	void *p;
	int n;

	/* our varargs are things to be freed. */
	va_start(ap, code);
	while (p = va_arg(ap, void *), p != NULL)
		DESTROY(p);
	va_end(ap);

	/* writers and readers which are still known, must be freed. */
	while (writers != NULL)
		writer_fini(writers);

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	/* globals which may have been initialized, are to be freed. */
	DESTROY(api_key);
	DESTROY(dnsdb_base_url);
#if WANT_PDNS_CIRCL
	DESTROY(circl_base_url);
	DESTROY(circl_authinfo);
#endif

	/* sort key specifications and computations, are to be freed. */
	for (n = 0; n < nkeys; n++) {
		DESTROY(keys[n].specified);
		DESTROY(keys[n].computed);
	}

	/* terminate process. */
	if (debuglev > 0)
		fprintf(stderr, "about to call exit(%d)\n", code);
	exit(code);
}

/* my_panic -- display an error on diagnostic output stream, exit ungracefully
 */
static __attribute__((noreturn)) void
my_panic(const char *s) {
	perror(s);
	my_exit(1, NULL);
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

/* validate_cmd_opts_lookup -- validate command line options for
 * a lookup verb
 */
static void
validate_cmd_opts_lookup(void)
{
	/* TODO too many local variables would need to be global to check
	 * more here
	 */
	if (max_count > 0)
		usage("max_count only allowed for a summarize verb");
}

/* validate_cmd_opts_summarize -- validate command line options for
 * a summarize verb
 */
static void
validate_cmd_opts_summarize(void)
{
	/* Remap the presentation format functions for the summarize variants */
	if (pres == present_json)
		pres = present_json_summarize;
	else if (pres == present_csv)
		pres = present_csv_summarize;
	else
		pres = present_text_summarize; /* default to text format */

	if (sorted != no_sort)
		usage("Sorting with a summarize verb makes no sense");
	/*TODO add more validations? */
}

/* or_else -- return one pointer or else the other. */
static const char *
or_else(const char *p, const char *or_else) {
	if (p != NULL)
		return p;
	return or_else;
}

/* add_sort_key -- add a key for use by POSIX sort.
 */
static const char *
add_sort_key(const char *tok) {
	const char *key = NULL;

	if (nkeys == MAX_KEYS)
		return ("too many sort keys given.");
	if (strcasecmp(tok, "first") == 0) {
		key = "-k1n";
	} else if (strcasecmp(tok, "last") == 0) {
		key = "-k2n";
	} else if (strcasecmp(tok, "count") == 0) {
		key = "-k3n";
	} else if (strcasecmp(tok, "name") == 0) {
		key = "-k4";
		sort_byname = true;
	} else if (strcasecmp(tok, "data") == 0) {
		key = "-k5";
		sort_bydata = true;
	}
	if (key == NULL)
		return ("key must be one of first, "
			"last, count, name, or data");
	keys[nkeys++] = (struct sortkey){strdup(tok), strdup(key)};
	return (NULL);
}

/* find_sort_key -- return pointer to a sort key, or NULL if it's not specified
 */
static sortkey_ct
find_sort_key(const char *tok) {
	int n;

	for (n = 0; n < nkeys; n++) {
		if (strcmp(keys[n].specified, tok) == 0)
			return (&keys[n]);
	}
	return (NULL);
}

/* find_pdns -- locate a pdns system's metadata by name.
 */
static pdns_sys_t
find_system(const char *name) {
	pdns_sys_t t;

	for (t = pdns_systems; t->name != NULL; t++)
		if (strcasecmp(t->name, name) == 0)
			return (t);
	return (NULL);
}

/* find_verb -- locate a verb by option parameter
 */
static verb_t
find_verb(const char *option) {
	verb_t v;

	for (v = verbs; v->cmd_opt_val != NULL; v++)
		if (strcasecmp(option, v->cmd_opt_val) == 0)
			return (v);
	return (NULL);
}

/* server_setup -- learn the server name and API key by various means.
 */
static void
server_setup(void) {
	read_configs();
	read_environ();
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
			if (debuglev > 0)
				fprintf(stderr, "conf found: '%s'\n", cf);
			break;
		}
		DESTROY(cf);
	}
	if (*conf != NULL) {
		char *cmd, *tok1, *tok2, *line;
		size_t n;
		FILE *f;
		int x, l;

		x = asprintf(&cmd,
			     ". %s;"
			     "echo apikey $APIKEY;"
			     "echo server $DNSDB_SERVER;"
#if WANT_PDNS_CIRCL
			     "echo circla $CIRCL_AUTH;"
			     "echo circls $CIRCL_SERVER;"
#endif
			     "exit", cf);
		if (x < 0)
			my_panic("asprintf");
		f = popen(cmd, "r");
		if (f == NULL) {
			perror(cmd);
			my_exit(1, cmd, NULL);
		}
		if (debuglev > 0)
			fprintf(stderr, "conf cmd = '%s'\n", cmd);
		DESTROY(cmd);
		line = NULL;
		n = 0;
		l = 0;
		while (getline(&line, &n, f) > 0) {
			char **pp;

			l++;
			if (strchr(line, '\n') == NULL) {
				fprintf(stderr,
					"%s: conf line #%d: too long\n",
					program_name, l);
				my_exit(1, cf, NULL);
			}
			tok1 = strtok(line, "\040\012");
			tok2 = strtok(NULL, "\040\012");
			if (tok1 == NULL) {
				fprintf(stderr,
					"%s: conf line #%d: malformed\n",
					program_name, l);
				my_exit(1, cf, NULL);
			}
			if (tok2 == NULL)
				continue;

			if (debuglev > 0)
				fprintf(stderr, "line #%d: sets %s\n",
					l, tok1);
			pp = NULL;
			if (strcmp(tok1, "apikey") == 0) {
				pp = &api_key;
			} else if (strcmp(tok1, "server") == 0) {
				pp = &dnsdb_base_url;
#if WANT_PDNS_CIRCL
			} else if (strcmp(tok1, "circla") == 0) {
				pp = &circl_authinfo;
			} else if (strcmp(tok1, "circls") == 0) {
				pp = &circl_base_url;
#endif
			} else
				abort();
			DESTROY(*pp);
			*pp = strdup(tok2);
		}
		DESTROY(line);
		pclose(f);
	}
	DESTROY(cf);
}

/* read_environ -- override the config file from environment variables?
 */
static void
read_environ() {
	const char *val;

	val = getenv(env_api_key);
	if (val != NULL) {
		if (api_key != NULL)
			DESTROY(api_key);
		api_key = strdup(val);
		if (debuglev > 0)
			fprintf(stderr, "conf env api_key was set\n");
	}
	val = getenv(env_dnsdb_base_url);
	if (val != NULL) {
		if (dnsdb_base_url != NULL)
			DESTROY(dnsdb_base_url);
		dnsdb_base_url = strdup(val);
		if (debuglev > 0)
			fprintf(stderr, "conf env dnsdb_server = '%s'\n",
				dnsdb_base_url);
	}
	if (api_key == NULL) {
		fprintf(stderr, "%s: no API key given\n", program_name);
		my_exit(1, NULL);
	}
}

/* do_batch -- implement "filter" mode, reading commands from a batch file.
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
		char *nl = strchr(command, '\n');

		/* the last line of the file may not have a newline. */
		if (nl != NULL)
			*nl = '\0';
		
		if (debuglev > 0)
			fprintf(stderr, "do_batch(%s)\n", command);

		/* if not merging, start a writer here instead. */
		if (!merge) {
			writer = writer_init(after, before);
			/* only verbose batching shows query startups. */
			if (batching == batch_verbose)
				fprintf(stdout, "++ %s\n", command);
		}

		/* start one or two curl jobs based on this search. */
		query_launcher(command, writer, after, before);

		/* if merging, drain some jobs; else, drain all jobs. */
		if (merge) {
			io_engine(MAX_JOBS);
		} else {
			io_engine(0);
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

/* makepath -- make a RESTful URI that describes these search parameters.
 */
static char *
makepath(mode_e mode, const char *name, const char *rrtype,
	 const char *bailiwick, const char *prefix_length)
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
			my_panic("asprintf");
		break;
	case name_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rdata/name/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rdata/name/%s",
				     name);
		if (x < 0)
			my_panic("asprintf");
		break;
	case ip_mode:
		if (prefix_length != NULL)
			x = asprintf(&command, "rdata/ip/%s,%s",
				     name, prefix_length);
		else
			x = asprintf(&command, "rdata/ip/%s",
				     name);
		if (x < 0)
			my_panic("asprintf");
		break;
	case raw_rrset_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rrset/raw/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rrset/raw/%s",
				     name);
		if (x < 0)
			my_panic("asprintf");
		break;
	case raw_name_mode:
		if (rrtype != NULL)
			x = asprintf(&command, "rdata/raw/%s/%s",
				     name, rrtype);
		else
			x = asprintf(&command, "rdata/raw/%s",
				     name);
		if (x < 0)
			my_panic("asprintf");
		break;
	case no_mode:
		/*FALLTHROUGH*/
	default:
		abort();
	}
	return (command);
}

/* make_curl -- perform global initializations of libcurl.
 */
static void
make_curl(void) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_cleanup_needed++;
	multi = curl_multi_init();
	if (multi == NULL) {
		fprintf(stderr, "curl_multi_init() failed\n");
		my_exit(1, NULL);
	}
}

/* unmake_curl -- clean up and discard libcurl's global state.
 */
static void
unmake_curl(void) {
	if (multi != NULL) {
		curl_multi_cleanup(multi);
		multi = NULL;
	}
	if (curl_cleanup_needed) {
		curl_global_cleanup();
		curl_cleanup_needed = 0;
	}
}

/* pdns_query -- launch one or more libcurl jobs to fulfill this DNSDB query.
 */
static void
pdns_query(const char *command, u_long after, u_long before) {
	writer_t writer;

	if (debuglev > 0)
		fprintf(stderr, "pdns_query(%s)\n", command);

	/* start a writer, which might be format functions, or POSIX sort. */
	writer = writer_init(after, before);

	/* start a small finite number of readers on that writer. */
	query_launcher(command, writer, after, before);
	
	/* run all jobs to completion. */
	io_engine(0);

	/* stop the writer, which might involve reading POSIX sort's output. */
	writer_fini(writer);
}

/* query_launcher -- fork off some curl jobs via launch() for this query.
 */
static void
query_launcher(const char *command, writer_t writer,
	       u_long after, u_long before)
{
	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (after != 0 && before != 0) {
		if (complete) {
			/* each db tuple must be enveloped by time fence. */
			launch(command, writer, after, 0, 0, before);
		} else {
			/* we need tuples that end after fence start... */
			launch(command, writer, 0, 0, after, 0);
			/* ...and that begin before the time fence end. */
			launch(command, writer, 0, before, 0, 0);
			/* and we will filter in reader_func() to
			 * select only those tuples which either:
			 * ...(start within), or (end within), or
			 * ...(start before and end after).
			 */
		}
	} else if (after != 0) {
		if (complete) {
			/* each db tuple must begin after the fence-start. */
			launch(command, writer, after, 0, 0, 0);
		} else {
			/* each db tuple must end after the fence-start. */
			launch(command, writer, 0, 0, after, 0);
		}
	} else if (before != 0) {
		if (complete) {
			/* each db tuple must end before the fence-end. */
			launch(command, writer, 0, 0, 0, before);
		} else {
			/* each db tuple must begin before the fence-end. */
			launch(command, writer, 0, before, 0, 0);
		}
	} else {
		/* no time fencing. */
		launch(command, writer, 0, 0, 0, 0);
	}
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

	url = sys->url(command, &sep);
	if (url == NULL)
		my_exit(1, NULL);

	if (query_limit != -1) {
		x = asprintf(&tmp, "%s%c" "limit=%d", url, sep, query_limit);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, url, NULL);
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
			my_exit(1, url, NULL);
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
			my_exit(1, url, NULL);
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
			my_exit(1, url, NULL);
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
			my_exit(1, url, NULL);
		}
		DESTROY(url);
		url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (debuglev > 0)
		fprintf(stderr, "url [%s]\n", url);

	launch_one(writer, url);
}

/* launch_one -- given a url, tell libcurl to go fetch it.
 */
static void
launch_one(writer_t writer, char *url) {
	reader_t reader = NULL;
	CURLMcode res;

	if (debuglev > 1)
		fprintf(stderr, "launch_one(%s)\n", url);
	CREATE(reader, sizeof *reader);
	reader->writer = writer;
	writer = NULL;
	reader->easy = curl_easy_init();
	if (reader->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		my_exit(1, reader, url, NULL);
	}
	reader->url = url;
	url = NULL;
	curl_easy_setopt(reader->easy, CURLOPT_URL, reader->url);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	sys->auth(reader);
	reader->hdrs = curl_slist_append(reader->hdrs, json_header);
	curl_easy_setopt(reader->easy, CURLOPT_HTTPHEADER, reader->hdrs);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEDATA, reader);
#if CURL_AT_LEAST_VERSION(7,42,0)
	/* do not allow curl to swallow /./ and /../ in our URLs */
	curl_easy_setopt(reader->easy, CURLOPT_PATH_AS_IS, 1L);
#endif /* CURL_AT_LEAST_VERSION */
	if (debuglev > 2)
		curl_easy_setopt(reader->easy, CURLOPT_VERBOSE, 1L);

	/* linked-list insert. */
	reader->next = reader->writer->readers;
	reader->writer->readers = reader;

	res = curl_multi_add_handle(multi, reader->writer->readers->easy);
	if (res != CURLM_OK) {
		fprintf(stderr, "curl_multi_add_handle() failed: %s\n",
			curl_multi_strerror(res));
		my_exit(1, NULL);
	}
}

/* rendezvous -- reap one reader.
 */
static void
rendezvous(reader_t reader) {
	if (reader->easy != NULL) {
		curl_multi_remove_handle(multi, reader->easy);
		curl_easy_cleanup(reader->easy);
		reader->easy = NULL;
	}
	if (reader->hdrs != NULL) {
		curl_slist_free_all(reader->hdrs);
		reader->hdrs = NULL;
	}
	DESTROY(reader->url);
	DESTROY(reader);
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

/* writer_init -- instantiate a writer, which may involve forking a "sort".
 */
static writer_t
writer_init(u_long after, u_long before) {
	writer_t writer = NULL;

	CREATE(writer, sizeof(struct writer));

	if (sorted != no_sort) {
		/* sorting involves a subprocess (POSIX sort(1) command),
		 * which will by definition not output anything until
		 * after it receives EOF. this means we can pipe both
		 * to its stdin and from its stdout, without risk of
		 * deadlock. it also means a full store-and-forward of
		 * the result, which increases latency to the first
		 * output for our user.
		 */
		int p1[2], p2[2];

		if (pipe(p1) < 0 || pipe(p2) < 0)
			my_panic("pipe");
		if ((writer->sort_pid = fork()) < 0)
			my_panic("fork");
		if (writer->sort_pid == 0) {
			char *sort_argv[3+MAX_KEYS], **sap;
			int n;

			if (dup2(p1[0], STDIN_FILENO) < 0 ||
			    dup2(p2[1], STDOUT_FILENO) < 0) {
				perror("dup2");
				_exit(1);
			}
			close(p1[0]); close(p1[1]);
			close(p2[0]); close(p2[1]);
			sap = sort_argv;
			*sap++ = strdup("sort");
			*sap++ = strdup("-u");
			for (n = 0; n < nkeys; n++) {
				int x = asprintf(sap++, "%s%s",
						 keys[n].computed,
						 sorted==reverse_sort?"r":"");
				if (x < 0)
					my_panic("asprintf");
			}
			*sap++ = NULL;
			putenv(strdup("LC_ALL=C"));
			if (debuglev > 0) {
				fprintf(stderr, "\"%s\" args:", path_sort);
				for (sap = sort_argv; *sap != NULL; sap++)
					fprintf(stderr, " [%s]", *sap);
				fputc('\n', stderr);
			}
			execve(path_sort, sort_argv, environ);
			perror("execve");
			for (sap = sort_argv; *sap != NULL; sap++)
				DESTROY(*sap);
			_exit(1);
		}
		close(p1[0]);
		writer->sort_stdin = fdopen(p1[1], "w");
		writer->sort_stdout = fdopen(p2[0], "r");
		close(p2[1]);
	}

	writer->after = after;
	writer->before = before;
	writer->next = writers;
	writers = writer;
	return (writer);
}

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
			time_print(tp->as_int, outf);
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

/* dnsdb_write_info -- assumes that reader contains the complete JSON block.
 */
static void
dnsdb_write_info(reader_t reader) {
	if (pres == present_text) {
		struct dnsdb_rate_tuple tup;
		const char *msg;
		msg = dnsdb_rate_tuple_make(&tup, reader->buf, reader->len);
		if (msg != NULL) { /* there was an error */
			puts(msg);
		} else {
			fprintf(stdout, "quota:\n");
			print_rateval("reset", &tup.reset, stdout);
			print_rateval("expires", &tup.expires, stdout);
			print_rateval("limit", &tup.limit, stdout);
			print_rateval("remaining", &tup.remaining, stdout);
			print_rateval("results_max", &tup.results_max, stdout);
			print_rateval("offset_max", &tup.offset_max, stdout);
			print_burstrate("burst rate",
					&tup.burst_size, &tup.burst_window,
					stdout);
		}
	} else if (pres == present_json) {
		fwrite(reader->buf, 1, reader->len, stdout);
	} else {
		abort();
	}
}

/* writer_status -- install a status code and description in a writer.
 */
static void
writer_status(writer_t writer, const char *status, const char *message) {
	assert((writer->status == NULL) == (writer->message == NULL));
	assert(writer->status == NULL);
	writer->status = strdup(status);
	writer->message = strdup(message);
}

/* writer_func -- process a block of json text, from filesys or API socket.
 */
static size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	reader_t reader = (reader_t) blob;
	size_t bytes = size * nmemb;
	u_long after, before;
	FILE *outf;
	char *nl;

	if (debuglev > 2)
		fprintf(stderr, "writer_func(%d, %d): %d\n",
			(int)size, (int)nmemb, (int)bytes);

	reader->buf = realloc(reader->buf, reader->len + bytes);
	memcpy(reader->buf + reader->len, ptr, bytes);
	reader->len += bytes;

	/* when the reader is a live web result, emit
	 * !2xx errors and info payloads as reports.
	 */
	if (reader->easy != NULL) {
		if (reader->rcode == 0)
			curl_easy_getinfo(reader->easy,
					  CURLINFO_RESPONSE_CODE,
					  &reader->rcode);
		if (reader->rcode != 200) {
			char *message = strndup(reader->buf, reader->len);
			char *newline = strchr(message, '\n');
			if (newline != NULL)
				*newline = '\0';

			if (!reader->writer->once) {
				writer_status(reader->writer,
					      sys->status(reader),
					      message);
				if (!quiet) {
					char *url;
					
					curl_easy_getinfo(reader->easy,
							 CURLINFO_EFFECTIVE_URL,
							  &url);
					fprintf(stderr,
						"%s: libcurl: %ld (%s)\n",
						program_name, reader->rcode,
						url);
				}
				reader->writer->once = true;
			}
			if (!quiet)
				fprintf(stderr, "%s: libcurl: [%s]\n",
					program_name, message);
			DESTROY(message);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}
	}

	after = reader->writer->after;
	before = reader->writer->before;
	outf = (sorted != no_sort) ? reader->writer->sort_stdin : stdout;

	while ((nl = memchr(reader->buf, '\n', reader->len)) != NULL) {
		size_t pre_len, post_len;

		if (info) {
			sys->write_info(reader);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}

		if (sorted == no_sort &&
		    output_limit != -1 &&
		    reader->writer->count >= output_limit)
		{
			if (debuglev > 2)
				fprintf(stderr,
					"hit output limit %d\n", output_limit);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}

		pre_len = (size_t)(nl - reader->buf);
		reader->writer->count += input_blob(reader->buf, pre_len,
						    after, before, outf);
		post_len = (reader->len - pre_len) - 1;
		memmove(reader->buf, nl + 1, post_len);
		reader->len = post_len;
	}
	return (bytes);
}

/* input_blob -- process one deblocked json blob as a counted string.
 */
static int
input_blob(const char *buf, size_t len,
	   u_long after, u_long before,
	   FILE *outf)
{
	const char *msg, *whynot;
	struct pdns_tuple tup;
	u_long first, last;
	int ret = 0;

	msg = tuple_make(&tup, buf, len);
	if (msg != NULL) {
		fputs(msg, stderr);
		fputc('\n', stderr);
		goto more;
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

	/* time fencing can in some cases (-A & -B w/o -c) require
	 * asking the server for more than we really want, and so
	 * we have to winnow it down upon receipt. (see also -J.)
	 */
	whynot = NULL;
	if (debuglev > 1)
		fprintf(stderr, "filtering-- ");
	if (after != 0) {
		int first_vs_after, last_vs_after;

		first_vs_after = timecmp(first, after);
		last_vs_after = timecmp(last, after);
		if (debuglev > 1)
			fprintf(stderr, "FvA %d LvA %d: ",
				first_vs_after, last_vs_after);

		if (complete) {
			if (first_vs_after < 0) {
				whynot = "first is too early";
			}
		} else {
			if (last_vs_after < 0) {
				whynot = "last is too early";
			}
		}
	}
	if (before != 0) {
		int first_vs_before, last_vs_before;

		first_vs_before = timecmp(first, before);
		last_vs_before = timecmp(last, before);
		if (debuglev > 1)
			fprintf(stderr, "FvB %d LvB %d: ",
				first_vs_before, last_vs_before);

		if (complete) {
			if (last_vs_before > 0) {
				whynot = "last is too late";
			}
		} else {
			if (first_vs_before > 0) {
				whynot = "first is too late";
			}
		}
	}

	if (whynot == NULL) {
		if (debuglev > 1)
			fprintf(stderr, "selected!\n");
	} else {
		if (debuglev > 1)
			fprintf(stderr, "skipped (%s).\n", whynot);
	}
	if (debuglev > 2) {
		fputs("\tF..L = ", stderr);
		time_print(first, stderr);
		fputs(" .. ", stderr);
		time_print(last, stderr);
		fputc('\n', stderr);
		fputs("\tA..B = ", stderr);
		time_print(after, stderr);
		fputs(" .. ", stderr);
		time_print(before, stderr);
		fputc('\n', stderr);
	}
	if (whynot != NULL)
		goto next;

	if (sorted != no_sort) {
		/* POSIX sort is given five extra fields at the
		 * front of each line (first, last, count)
		 * which are accessed as -k1 .. -k5 on the
		 * sort command line. we strip them off later
		 * when reading the result back. the reason
		 * for all this PDP11-era logic is to avoid
		 * having to store the full result in memory.
		 */
		char *dyn_rrname = NULL, *dyn_rdata = NULL;
		if (sort_byname) {
			dyn_rrname = sortable_rrname(&tup);
			if (debuglev > 1) {
				fprintf(stderr, "dyn_rrname = '%s'\n",
					dyn_rrname);
			}
		}
		if (sort_bydata) {
			dyn_rdata = sortable_rdata(&tup);
			if (debuglev > 1) {
				fprintf(stderr, "dyn_rdata = '%s'\n",
					dyn_rdata);
			}
		}
		fprintf(outf, "%lu %lu %lu %s %s %*.*s\n",
			(unsigned long)first,
			(unsigned long)last,
			(unsigned long)tup.count,
			or_else(dyn_rrname, "n/a"),
			or_else(dyn_rdata, "n/a"),
			(int)len, (int)len, buf);
		if (debuglev > 1) {
			fprintf(stderr, "sort0: '%lu %lu %lu %s %s %*.*s'\n",
				(unsigned long)first,
				(unsigned long)last,
				(unsigned long)tup.count,
				or_else(dyn_rrname, "n/a"),
				or_else(dyn_rdata, "n/a"),
				(int)len, (int)len, buf);
		}
		DESTROY(dyn_rrname);
		DESTROY(dyn_rdata);
	} else {
		(*pres)(&tup, buf, len, outf);
	}
	ret = 1;
 next:
	tuple_unmake(&tup);
 more:
	return (ret);
}

/* writer_fini -- stop a writer's readers, and perhaps execute a POSIX "sort".
 */
static void
writer_fini(writer_t writer) {
	/* unlink this writer from the global chain. */
	if (writers == writer) {
		writers = writer->next;
	} else {
		writer_t prev = NULL;
		writer_t temp;

		for (temp = writers; temp != NULL; temp = temp->next) {
			if (temp->next == writer) {
				prev = temp;
				break;
			}
		}
		if (prev == NULL) {
			fprintf(stderr, "writer_fini(): no prev found.\n");
			abort();
		}
		prev->next = writer->next;
	}

	/* finish and close any readers still cooking. */
	while (writer->readers != NULL) {
		reader_t reader = writer->readers;

		/* release any buffered info. */
		DESTROY(reader->buf);
		if (reader->len != 0) {
			fprintf(stderr, "stranding %d octets!\n",
				(int)reader->len);
			reader->len = 0;
		}

		/* tear down any curl infrastructure on the reader & remove. */
		reader_t next = reader->next;
		rendezvous(reader);
		reader = NULL;
		writer->readers = next;
	}

	/* drain the sort if there is one. */
	if (writer->sort_pid != 0) {
		int status, count;
		char *line = NULL;
		size_t n = 0;

		/* when sorting, there has been no output yet. gather the
		 * intermediate representation from the POSIX sort stdout,
		 * skip over the sort keys we added earlier, and process.
		 */
		fclose(writer->sort_stdin);
		if (debuglev > 0)
			fprintf(stderr,
				"closed sort_stdin, wrote %d objs\n",
				writer->count);
		count = 0;
		while (getline(&line, &n, writer->sort_stdout) > 0) {
			/* if we're above the limit, ignore remaining output.
			 * this is nec'y to avoid SIGPIPE from sort if we were
			 * to close its stdout pipe without emptying it first.
			 */
			if (output_limit != -1 && count >= output_limit) {
				if (!writer->sort_killed) {
					kill(writer->sort_pid, SIGTERM);
					writer->sort_killed = true;
				}
				continue;
			}

			char *nl, *linep;
			const char *msg;
			struct pdns_tuple tup;

			if ((nl = strchr(line, '\n')) == NULL) {
				fprintf(stderr, "no \\n found in '%s'\n",
					line);
				continue;
			}
			linep = line;
			if (debuglev > 1) {
				fprintf(stderr, "sort1: '%*.*s'\n",
					(int)(nl - linep),
					(int)(nl - linep),
					linep);
			}
			/* skip sort keys (first, last, count, name, data). */
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"no SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"no second SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"no third SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"no fourth SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"no fifth SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if (debuglev > 1) {
				fprintf(stderr, "sort2: '%*.*s'\n",
					(int)(nl - linep),
					(int)(nl - linep),
					linep);
			}
			msg = tuple_make(&tup, linep, (size_t)(nl - linep));
			if (msg != NULL) {
				fprintf(stderr, "tuple_make: %s\n", msg);
				continue;
			}
			(*pres)(&tup, linep, (size_t)(nl - linep), stdout);
			tuple_unmake(&tup);
			count++;
		}
		DESTROY(line);
		fclose(writer->sort_stdout);
		if (debuglev > 0)
			fprintf(stderr,
				"closed sort_stdout, read %d objs (lim %d)\n",
				count, query_limit);
		if (waitpid(writer->sort_pid, &status, 0) < 0) {
			perror("waitpid");
		} else {
			if (!writer->sort_killed && status != 0)
				fprintf(stderr, "sort exit status is %u\n",
					status);
		}
	}

	/* drop message and status strings if present. */
	assert((writer->status != NULL) == (writer->status != NULL));
	if (writer->status != NULL)
		DESTROY(writer->status);
	if (writer->message != NULL)
		DESTROY(writer->message);

	DESTROY(writer);
}

/* io_engine -- let libcurl run until there are few enough outstanding jobs.
 */
static void
io_engine(int jobs) {
	int still, repeats, numfds;
	struct CURLMsg *cm;

	if (debuglev > 1)
		fprintf(stderr, "io_engine(%d)\n", jobs);

	/* let libcurl run while there are too many jobs remaining. */
	still = 0;
	repeats = 0;
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > jobs) {
		if (debuglev > 3)
			fprintf(stderr, "...waiting (still %d)\n", still);
		numfds = 0;
		if (curl_multi_wait(multi, NULL, 0, 0, &numfds) != CURLM_OK)
			break;
		if (numfds == 0) {
			if (++repeats > 1)
				usleep(100000);
		} else {
			repeats = 0;
		}
	}

	/* drain the response code reports. */
	still = 0;
	while ((cm = curl_multi_info_read(multi, &still)) != NULL) {
		if (cm->msg == CURLMSG_DONE && cm->data.result != CURLE_OK) {
			if (cm->data.result == CURLE_COULDNT_RESOLVE_HOST)
				fprintf(stderr, "libcurl failed since "
						"could not resolve host\n");
			else if (cm->data.result == CURLE_COULDNT_CONNECT)
				fprintf(stderr, "libcurl failed since "
						"could not connect\n");
			else
				fprintf(stderr, "libcurl failed with "
						"curl error %d\n",
					cm->data.result);
			exit_code = 1;
		}
		if (debuglev > 3)
			fprintf(stderr, "...info read (still %d)\n", still);
	}
}

/* present_text -- render one pdns tuple in "dig" style ascii text.
 */
static void
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
		fputs(";; record times: ", outf);
		time_print(tup->time_first, outf);
		fputs(" .. ", outf);
		time_print(tup->time_last, outf);
		putc('\n', outf);
		ppflag = true;
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		fputs(";;   zone times: ", outf);
		time_print(tup->zone_first, outf);
		fputs(" .. ", outf);
		time_print(tup->zone_last, outf);
		putc('\n', outf);
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
static void
present_text_summarize(pdns_tuple_ct tup,
	     const char *jsonbuf __attribute__ ((unused)),
	     size_t jsonlen __attribute__ ((unused)),
	     FILE *outf)
{
	const char *prefix;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		fputs(";; record times: ", outf);
		time_print(tup->time_first, outf);
		fputs(" .. ", outf);
		time_print(tup->time_last, outf);
		putc('\n', outf);
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		fputs(";;   zone times: ", outf);
		time_print(tup->zone_first, outf);
		fputs(" .. ", outf);
		time_print(tup->zone_last, outf);
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
static void
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
static void
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
static void
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
static void
present_csv_line(pdns_tuple_ct tup,
		 const char *rdata,
		 FILE *outf)
{
	/* Timestamps. */
	if (tup->obj.time_first != NULL) {
		putc('"', outf);
		time_print(tup->time_first, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.time_last != NULL) {
		putc('"', outf);
		time_print(tup->time_last, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.zone_first != NULL) {
		putc('"', outf);
		time_print(tup->zone_first, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.zone_last != NULL) {
		putc('"', outf);
		time_print(tup->zone_last, outf);
		putc('"', outf);
	}
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
static void
present_csv_summarize(pdns_tuple_ct tup,
	    const char *jsonbuf __attribute__ ((unused)),
	    size_t jsonlen __attribute__ ((unused)),
	    FILE *outf)
{
	fprintf(outf,
		"time_first,time_last,zone_first,zone_last,"
		"count,num_results\n");

	/* Timestamps. */
	if (tup->obj.time_first != NULL) {
		putc('"', outf);
		time_print(tup->time_first, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.time_last != NULL) {
		putc('"', outf);
		time_print(tup->time_last, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.zone_first != NULL) {
		putc('"', outf);
		time_print(tup->zone_first, outf);
		putc('"', outf);
	}
	putc(',', outf);
	if (tup->obj.zone_last != NULL) {
		putc('"', outf);
		time_print(tup->zone_last, outf);
		putc('"', outf);
	}
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
static const char *
tuple_make(pdns_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

	memset(tup, 0, sizeof *tup);
	if (debuglev > 2)
		fprintf(stderr, "[%d] '%-*.*s'\n",
			(int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%d:%d: %s %s\n",
			error.line, error.column,
			error.text, error.source);
		abort();
	}
	if (debuglev > 3) {
		json_dumpf(tup->obj.main, stderr, JSON_INDENT(2));
		fputc('\n', stderr);
	}

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
static void
tuple_unmake(pdns_tuple_t tup) {
	json_decref(tup->obj.main);
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

/* dnsdb_rate_tuple_make -- create one rate tuple object out of a JSON object.
 */
static const char *
dnsdb_rate_tuple_make(dnsdb_rate_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;
	json_t *rate;

	memset(tup, 0, sizeof *tup);
	if (debuglev > 2)
		fprintf(stderr, "[%d] '%-*.*s'\n",
			(int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%d:%d: %s %s\n",
			error.line, error.column,
			error.text, error.source);
		abort();
	}
	if (debuglev > 3) {
		json_dumpf(tup->obj.main, stderr, JSON_INDENT(2));
		fputc('\n', stderr);
	}

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
	dnsdb_rate_tuple_unmake(tup);
	return (msg);
}

/* dnsdb_rate_tuple_unmake -- deallocate heap storage associated with
 * one rate tuple.
 */
static void
dnsdb_rate_tuple_unmake(dnsdb_rate_tuple_t tup) {
	json_decref(tup->obj.main);
}

/* timecmp -- compare two absolute timestamps, give -1, 0, or 1.
 */
static int
timecmp(u_long a, u_long b) {
	if (a < b)
		return (-1);
	if (a > b)
		return (1);
	return (0);
}

/* time_print -- format one (possibly relative) timestamp.
 */
static void
time_print(u_long x, FILE *outf) {
	if (x == 0) {
		fputs("0", outf);
	} else {
		const char *val;
		time_t t = (time_t)x;
		struct tm *y = gmtime(&t);
		char z[99];
		/* only allow "iso" or "csv", but default to "csv",
		 * so only "iso" matters.
		 */
		val = getenv(env_time_fmt);
		if (val != NULL && strcmp(val, "iso") == 0)
			strftime(z, sizeof z, "%FT%TZ", y);
		else
			strftime(z, sizeof z, "%F %T", y);
		fputs(z, outf);
	}
}

/* time_get -- parse and return one (possibly relative) timestamp.
 */
static int
time_get(const char *src, u_long *dst) {
	struct tm tt;
	long long ll;
	u_long t;
	char *ep;

	memset(&tt, 0, sizeof tt);
	if (((ep = strptime(src, "%F %T", &tt)) != NULL && *ep == '\0') ||
	    ((ep = strptime(src, "%F", &tt)) != NULL && *ep == '\0'))
	{
		*dst = (u_long)(timegm(&tt));
		return (1);
	}
	ll = strtoll(src, &ep, 10);
	if (*src != '\0' && *ep == '\0') {
		if (ll < 0)
			*dst = (u_long)now.tv_sec - (u_long)imaxabs(ll);
		else
			*dst = (u_long)ll;
		return (1);
	}
	if (ns_parse_ttl(src, &t) == 0) {
		*dst = (u_long)now.tv_sec - t;
		return (1);
	}
	return (0);
}

/* escape -- HTML-encode a string, in place.
 */
static void
escape(char **src) {
	char *escaped;

	escaped = curl_escape(*src, (int)strlen(*src));
	if (escaped == NULL) {
		fprintf(stderr, "curl_escape(%s) failed\n", *src);
		my_exit(1, NULL);
	}
	DESTROY(*src);
	*src = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
}

/* sortable_rrname -- return a POSIX-sort-collatable rendition of RR name+type.
 */
static char *
sortable_rrname(pdns_tuple_ct tup) {
	struct sortbuf buf = {NULL, 0};

	sortable_dnsname(&buf, tup->rrname);
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return (buf.base);
}

/* sortable_rdata -- return a POSIX-sort-collatable rendition of RR data set.
 */
static char *
sortable_rdata(pdns_tuple_ct tup) {
	struct sortbuf buf = {NULL, 0};

	if (json_is_array(tup->obj.rdata)) {
		size_t slot, nslots;

		nslots = json_array_size(tup->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(tup->obj.rdata, slot);

			if (json_is_string(rr))
				sortable_rdatum(&buf, tup->rrtype,
						json_string_value(rr));
			else
				fprintf(stderr, "rdata slot not a string?\n");
		}
	} else {
		sortable_rdatum(&buf, tup->rrtype, tup->rdata);
	}
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return (buf.base);
}

/* sortable_rdatum -- called only by sortable_rdata(), realloc and normalize.
 *
 * this converts (lossily) addresses into hex strings, and extracts the
 * server-name component of a few other types like MX. all other rdata
 * are left in their normal string form, because it's hard to know what
 * to sort by with something like TXT, and extracting the serial number
 * from an SOA using a language like C is a bit ugly.
 */
static void
sortable_rdatum(sortbuf_t buf, const char *rrtype, const char *rdatum) {
	if (strcmp(rrtype, "A") == 0) {
		u_char a[4];

		if (inet_pton(AF_INET, rdatum, a) != 1)
			memset(a, 0, sizeof a);
		sortable_hexify(buf, a, sizeof a);
	} else if (strcmp(rrtype, "AAAA") == 0) {
		u_char aaaa[16];

		if (inet_pton(AF_INET6, rdatum, aaaa) != 1)
			memset(aaaa, 0, sizeof aaaa);
		sortable_hexify(buf, aaaa, sizeof aaaa);
	} else if (strcmp(rrtype, "NS") == 0 ||
		   strcmp(rrtype, "PTR") == 0 ||
		   strcmp(rrtype, "CNAME") == 0)
	{
		sortable_dnsname(buf, rdatum);
	} else if (strcmp(rrtype, "MX") == 0 ||
		   strcmp(rrtype, "RP") == 0)
	{
		const char *space = strrchr(rdatum, ' ');

		if (space != NULL)
			sortable_dnsname(buf, space+1);
		else
			sortable_hexify(buf, (const u_char *)rdatum,
					strlen(rdatum));
	} else {
		sortable_hexify(buf, (const u_char *)rdatum, strlen(rdatum));
	}
}

static void
sortable_hexify(sortbuf_t buf, const u_char *src, size_t len) {
	size_t i;

	buf->base = realloc(buf->base, buf->size + len*2);
	for (i = 0; i < len; i++) {
		const char hex[] = "0123456789abcdef";
		unsigned int ch = src[i];

		buf->base[buf->size++] = hex[ch >> 4];
		buf->base[buf->size++] = hex[ch & 0xf];
	}
}

/* sortable_dnsname -- make a sortable dns name; destructive and lossy.
 *
 * to be lexicographically sortable, a dnsname has to be converted to
 * TLD-first, all uppercase letters must be converted to lower case,
 * and all characters except dots then converted to hexadecimal. this
 * transformation is for POSIX sort's use, and is irreversibly lossy.
 */
static void
sortable_dnsname(sortbuf_t buf, const char *name) {
	const char hex[] = "0123456789abcdef";
	size_t len, new_size;
	unsigned int dots;
	signed int m, n;
	char *p;

	/* to avoid calling realloc() on every label, count the dots. */
	for (dots = 0, len = 0; name[len] != '\0'; len++) {
		if (name[len] == '.')
			dots++;
	}

	/* collatable names are TLD-first, all lower case. */
	new_size = buf->size + len*2 - (size_t)dots;
	assert(new_size != 0);
	if (new_size != buf->size)
		buf->base = realloc(buf->base, new_size);
	p = buf->base + buf->size;
	for (m = (int)len - 1, n = m; m >= 0; m--) {
		/* note: actual presentation form names can have \. and \\,
		 * but we are destructive and lossy, and will ignore that.
		 */
		if (name[m] == '.') {
			int i;

			for (i = m+1; i <= n; i++) {
				int ch = tolower(name[i]);
				*p++ = hex[ch >> 4];
				*p++ = hex[ch & 0xf];
			}
			*p++ = '.';
			n = m-1;
		}
	}
	assert(m == -1);
	/* first label remains after loop. */
	for (m = 0; m <= n; m++) {
		int ch = tolower(name[m]);
		*p++ = hex[ch >> 4];
		*p++ = hex[ch & 0xf];
	}
	buf->size = (size_t)(p - buf->base);
	assert(buf->size == new_size);
	/* if no characters were written, it's the empty string,
	 * meaning the dns root zone.
	 */
	if (len == 0) {
		buf->base = realloc(buf->base, buf->size + 1);
		buf->base[buf->size++] = '.';
	}
}

/* dnsdb_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 */
static char *
dnsdb_url(const char *path, char *sep) {
	char max_count_if_needed[sizeof "&max_count=##################"] = "";
	char offset_if_needed[sizeof "&offset=##################"] = "";
	const char *verb_path, *p, *scheme_if_needed, *aggr_if_needed;
	char *ret;
	int x;

	/* if the config file didn't specify our server, do it here. */
	if (dnsdb_base_url == NULL)
		dnsdb_base_url = strdup(sys->base_url);
	assert(dnsdb_base_url != NULL);

	/* count the number of slashes in the url, 2 is the base line,
	 * from "//".  3 or more means there's a /path after the host.
	 * In that case, don't add /[verb] here, but don't allow
	 * selecting a verb that's not lookup since the /path could
	 * include its own verb
	 */
	x = 0;
	for (p = dnsdb_base_url; *p != '\0'; p++)
		x += (*p == '/');
	if (x < 3)
		if (chosen_verb != NULL && chosen_verb->url_fragment != NULL)
			verb_path = chosen_verb->url_fragment;
		else
			verb_path = "/lookup";
	else if (chosen_verb != &verbs[0])
		usage("Cannot specify a verb other than 'lookup' "
		      "if the server contains a path");
	else
		verb_path = "";

	/* supply a scheme if the server string did not. */
	scheme_if_needed = "";
	if (strstr(dnsdb_base_url, "://") == NULL)
		scheme_if_needed = "https://";

	aggr_if_needed = "";
	if (gravel)
		aggr_if_needed = "&aggr=f";

	if (offset > 0) {
		x = snprintf(offset_if_needed, sizeof offset_if_needed,
			     "&offset=%ld", offset);
		if (x < 0) {
			perror("snprintf");
			ret = NULL;
		}
	}

	if (max_count > 0) {
		x = snprintf(max_count_if_needed, sizeof max_count_if_needed,
			     "&max_count=%ld", max_count);
		if (x < 0) {
			perror("snprintf");
			ret = NULL;
		}
	}

	x = asprintf(&ret, "%s%s%s/%s?swclient=%s&version=%s%s%s%s",
		     scheme_if_needed, dnsdb_base_url, verb_path, path,
		     id_swclient, id_version, aggr_if_needed,
		     offset_if_needed, max_count_if_needed);
	if (x < 0) {
		perror("asprintf");
		ret = NULL;
	}

	/* because we append query parameters, tell the caller to use & for
	 * any further query parameters.
	 */
	if (sep != NULL)
		*sep = '&';

	return (ret);
}

static void
dnsdb_request_info(void) {
	writer_t writer;

	if (debuglev > 0)
		fprintf(stderr, "dnsdb_request_info()\n");

	/* start a writer, which might be format functions, or POSIX sort. */
	writer = writer_init(0, 0);

	/* start a status fetch. */
	launch_one(writer, dnsdb_url("rate_limit", NULL));

	/* run all jobs to completion. */
	io_engine(0);

	/* stop the writer, which might involve reading POSIX sort's output. */
	writer_fini(writer);
}

static void
dnsdb_auth(reader_t reader) {
	if (api_key != NULL) {
		char *key_header;

		if (asprintf(&key_header, "X-Api-Key: %s", api_key) < 0)
			my_panic("asprintf");
		reader->hdrs = curl_slist_append(reader->hdrs, key_header);
		DESTROY(key_header);
	}
}

static const char *
dnsdb_status(reader_t reader) {
	/* early (current) versions of DNSDB returns 404 for "no rrs found". */
	if (reader->rcode == 404)
		return "NOERROR";
	return "ERROR";
}

static bool
dnsdb_validate_verb(__attribute__((unused)) const char *verb_name) {
	/* All verbs are valid (currently) */
	return (true);
}

#if WANT_PDNS_CIRCL
/* circl_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 *
 * CIRCL pDNS only "understands IP addresses, hostnames or domain names
 * (please note that CIDR block queries are not supported)". exit with an
 * error message if asked to do something the CIRCL server does not handle.
 *
 * 1. RRSet query: rrset/name/NAME[/TYPE[/BAILIWICK]]
 * 2. Rdata (name) query: rdata/name/NAME[/TYPE]
 * 3. Rdata (IP address) query: rdata/ip/ADDR[/PFXLEN]
 */
static char *
circl_url(const char *path, char *sep) {
	const char *val = NULL;
	char *ret;
	int x, pi;
	/* NULL-terminate array of valid query paths for CIRCL */
	const char *valid_paths[] =
		{ "rrset/name/", "rdata/name/", "rdata/ip/", NULL };

	if (circl_base_url == NULL)
		circl_base_url = strdup(sys->base_url);

	for (pi = 0; valid_paths[pi] != NULL; pi++)
		if (strncasecmp(path, valid_paths[pi], strlen(valid_paths[pi]))
		    == 0) {
			val = path + strlen(valid_paths[pi]);
			break;
		}
	if (valid_paths[pi] == NULL) {
		fprintf(stderr,
			"Unsupported type of query for CIRCL pDNS: %s\n",
			path);
		my_exit(1, NULL);
	}

	if (strchr(val, '/') != NULL) {
		fprintf(stderr, "Qualifiers not supported by CIRCL pDNS: %s\n",
			val);
		my_exit(1, NULL);
	}
	x = asprintf(&ret, "%s/%s", circl_base_url, val);
	if (x < 0)
		my_panic("asprintf");

	/* because we will NOT append query parameters,
	 * tell the caller to use ? for its query parameters.
	 */
	if (sep != NULL)
		*sep = '?';

	return (ret);
}

static void
circl_auth(reader_t reader) {
	if (reader->easy != NULL) {
		curl_easy_setopt(reader->easy, CURLOPT_USERPWD,
				 circl_authinfo);
		curl_easy_setopt(reader->easy, CURLOPT_HTTPAUTH,
				 CURLAUTH_BASIC);
	}
}

static const char *
circl_status(reader_t reader __attribute__((unused))) {
	return "ERROR";
}

static bool
circl_validate_verb(const char *verb_name) {
	/* Only "lookup" is valid */
	if (strcasecmp(verb_name, "lookup") == 0)
		return (true);
	return (false);
}

#endif /*WANT_PDNS_CIRCL*/
