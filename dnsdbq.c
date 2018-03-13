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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

#include <curl/curl.h>
#include <jansson.h>
#include "ns_ttl.h"

extern char **environ;

/* Types. */

struct dnsdb_json {
	json_t		*main,
			*time_first, *time_last, *zone_first, *zone_last,
			*bailiwick, *rrname, *rrtype, *rdata,
			*count;
};

struct dnsdb_tuple {
	struct dnsdb_json  obj;
	u_long		time_first, time_last, zone_first, zone_last;
	const char	*bailiwick, *rrname, *rrtype, *rdata;
	json_int_t	count;
};
typedef struct dnsdb_tuple *dnsdb_tuple_t;

typedef void (*present_t)(const dnsdb_tuple_t, const char *, size_t, FILE *);

struct reader {
	struct reader		*next;
	struct writer		*writer;
	CURL			*easy;
	struct curl_slist	*hdrs;
	char			*url;
	char			*buf;
	size_t			len;
};
typedef struct reader *reader_t;

struct writer {
	struct writer		*next;
	struct reader		*readers;
	u_long			after;
	u_long			before;
	FILE			*sort_stdin;
	FILE			*sort_stdout;
	pid_t			sort_pid;
	int			count;
};
typedef struct writer *writer_t;

typedef enum { no_mode = 0, rdata_mode, name_mode, ip_mode } mode_e;

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
static const char default_server[] = "https://api.dnsdb.info";
static const char default_prefix[] = "/lookup";
static const char env_api_key[] = "DNSDB_API_KEY";
static const char env_dnsdb_server[] = "DNSDB_SERVER";

#define	MAX_KEYS 3
#define	MAX_JOBS 8

#define DESTROY(p) if (p != NULL) { free(p); p = NULL; } else {}

/* Forward. */

static void help(void);
static __attribute__((noreturn)) void usage(const char *);
static __attribute__((noreturn)) void my_exit(int, ...);
static void server_setup(void);
static void read_configs(void);
static void read_environ(void);
static void do_batch(FILE *, u_long, u_long);
static char *makepath(mode_e, const char *, const char *,
		      const char *, const char *);
static char *makeurl(const char *);
static void make_curl(void);
static void unmake_curl(void);
static void dnsdb_query(const char *, u_long, u_long);
static void query_launcher(const char *, writer_t, u_long, u_long);
static void launch(const char *, writer_t, u_long, u_long, u_long, u_long);
static void rendezvous(reader_t);
static void ruminate_json(int, u_long, u_long);
static writer_t writer_init(u_long, u_long);
static size_t writer_func(char *ptr, size_t size, size_t nmemb, void *blob);
static void writer_fini(writer_t);
static int reader_error(reader_t);
static void io_engine(int);
static void present_dns(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_json(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_csv(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_csv_line(const dnsdb_tuple_t, const char *, FILE *);
static const char *tuple_make(dnsdb_tuple_t, char *, size_t);
static void tuple_unmake(dnsdb_tuple_t);
static int timecmp(u_long, u_long);
static void time_print(u_long x, FILE *);
static int time_get(const char *src, u_long *dst);
static void escape(char **);

/* Private. */

static const char *program_name = NULL;
static char *api_key = NULL;
static char *key_header = NULL;
static char *dnsdb_server = NULL;
static char *api_prefix = NULL;
static enum { sys_dnsdb = 0 } api_system = sys_dnsdb;
static bool batch = false;
static bool merge = false;
static bool complete = false;
static int debuglev = 0;
static enum { no_sort = 0, normal_sort, reverse_sort } sorted = no_sort;
static int curl_cleanup_needed = 0;
static present_t pres = present_dns;
static int limit = 0;
static CURLM *multi = NULL;
static struct timeval now;
static struct timezone here;
static int nkeys, keys[MAX_KEYS];
static writer_t writers = NULL;

/* Public. */

int
main(int argc, char *argv[]) {
	mode_e mode = no_mode;
	char *name = NULL, *type = NULL, *bailiwick = NULL, *length = NULL;
	u_long after = 0;
	u_long before = 0;
	int json_fd = -1;
	int ch;

	/* global dynamic initialization. */
	gettimeofday(&now, &here);
	program_name = strrchr(argv[0], '/');
	if (program_name != NULL)
		program_name++;
	else
		program_name = argv[0];

	/* process the command line options. */
	while ((ch = getopt(argc, argv,
			    "A:B:r:n:i:l:a:u:p:t:b:k:J:djfmsShc")) != -1)
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
		case 'r': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, or -i can only appear once");
			assert(name == NULL);
			mode = rdata_mode;
			if (type == NULL && bailiwick == NULL)
				p = strchr(optarg, '/');
			else
				p = NULL;
			if (p != NULL) {
				const char *q;

				q = strchr(p + 1, '/');
				if (q != NULL) {
					bailiwick = strdup(q + 1);
					type = strndup(p + 1,
						       (size_t)(q - p - 1));
				} else {
					type = strdup(p + 1);
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
				usage("-r, -n, or -i can only appear once");
			assert(name == NULL);
			mode = name_mode;
			if (type == NULL)
				p = strchr(optarg, '/');
			else
				p = NULL;
			if (p != NULL) {
				if (strchr(p + 1, '/') != NULL)
					usage("-n must be NAME[/TYPE] only");
				name = strndup(optarg, (size_t)(p - optarg));
				type = strdup(p + 1);
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'i': {
			const char *p;

			if (mode != no_mode)
				usage("-r, -n, or -i can only appear once");
			assert(name == NULL);
			mode = ip_mode;
			p = strchr(optarg, '/');
			if (p != NULL) {
				name = strndup(optarg, (size_t)(p - optarg));
				length = strdup(p + 1);
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'l':
			limit = atoi(optarg);
			if (limit <= 0)
				usage("-l must be positive");
			break;
		case 'a':
			if (api_prefix != NULL)
				free(api_prefix);
			api_prefix = strdup(optarg);
			break;
		case 'u':
			if (strcasecmp(optarg, "dnsdb") == 0)
				api_system = sys_dnsdb;
			else
				usage("-u can only be 'dnsdb' right now");
			break;
		case 'p':
			if (strcmp(optarg, "json") == 0)
				pres = present_json;
			else if (strcmp(optarg, "dns") == 0)
				pres = present_dns;
			else if (strcmp(optarg, "csv") == 0)
				pres = present_csv;
			else
				usage("-p must specify json, dns, or csv");
			break;
		case 't':
			if (type != NULL)
				free(type);
			type = strdup(optarg);
			break;
		case 'b':
			if (bailiwick != NULL)
				free(bailiwick);
			bailiwick = strdup(optarg);
			break;
		case 'k': {
			const char *tok;

			nkeys = 0;
			for (tok = strtok(optarg, ",");
			     tok != NULL;
			     tok = strtok(NULL, ","))
			{
				int key = 0;

				if (nkeys == MAX_KEYS)
					usage("too many -k options given.");
				if (strcasecmp(tok, "first") == 0)
					key = 1;
				else if (strcasecmp(tok, "last") == 0)
					key = 2;
				else if (strcasecmp(tok, "count") == 0)
					key = 3;
				else
					usage("-k !< {first,last,count}");
				keys[nkeys++] = key;
			}
			break;
		    }
		case 'J':
			if (strcmp(optarg, "-") == 0)
				json_fd = STDIN_FILENO;
			else
				json_fd = open(optarg, O_RDONLY);
			if (json_fd < 0) {
				perror(optarg);
				my_exit(1, NULL);
			}
			break;
		case 'd':
			debuglev++;
			break;
		case 'j':
			pres = present_json;
			break;
		case 'f':
			batch = true;
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
		case 'h':
			help();
			my_exit(0, NULL);
		default:
			usage("unrecognized option");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage("there are no non-option arguments to this program");

	/* recondition various options for HTML use. */
	if (name != NULL)
		escape(&name);
	if (type != NULL)
		escape(&type);
	if (bailiwick != NULL)
		escape(&bailiwick);
	if (length != NULL)
		escape(&length);

	/* optionally dump program options as interpreted. */
	if (debuglev > 0) {
		if (name != NULL)
			fprintf(stderr, "name = '%s'\n", name);
		if (type != NULL)
			fprintf(stderr, "type = '%s'\n", type);
		if (bailiwick != NULL)
			fprintf(stderr, "bailiwick = '%s'\n", bailiwick);
		if (length != NULL)
			fprintf(stderr, "length = '%s'\n", length);
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
		if (limit != 0)
			fprintf(stderr, "limit = %d\n", limit);
		fprintf(stderr, "batch=%d, merge=%d\n", batch, merge);
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
	if (nkeys > 0 && sorted == no_sort)
		usage("using -k without -s or -S makes no sense.");
	if (merge && !batch)
		usage("using -m without -f makes no sense.");

	/* get some input from somewhere, and use it to drive our output. */
	if (json_fd != -1) {
		if (mode != no_mode)
			usage("can't mix -n, -r, or -i with -J");
		if (batch)
			usage("can't mix -f with -J");
		if (bailiwick != NULL)
			usage("can't mix -b with -J");
		ruminate_json(json_fd, after, before);
		close(json_fd);
	} else if (batch) {
		if (mode != no_mode)
			usage("can't mix -n, -r, or -i with -f");
		if (bailiwick != NULL)
			usage("can't mix -b with -f");
		if (type != NULL)
			usage("can't mix -t with -f");
		server_setup();
		make_curl();
		do_batch(stdin, after, before);
		unmake_curl();
	} else {
		char *command;

		if (mode == no_mode)
			usage("must specify -r, -n, or -i"
			      " unless -f or -J is used");
		if (bailiwick != NULL) {
			if (mode == ip_mode)
				usage("can't mix -b with -i");
			if (mode == name_mode)
				usage("can't mix -b with -n");
		}

		command = makepath(mode, name, type, bailiwick, length);
		server_setup();
		make_curl();
		dnsdb_query(command, after, before);
		DESTROY(command);
		unmake_curl();
	}

	/* clean up and go. */
	DESTROY(name);
	DESTROY(type);
	DESTROY(bailiwick);
	DESTROY(length);
	my_exit(0, NULL);
}

/* Private. */

/* help -- display a brief usage-help text; then exit.
 */
static void
help(void) {
	fprintf(stderr,
"usage: %s [-vdjsShc] [-p dns|json|csv] [-k (first|last|count)[,...]]\n"
"\t[-l LIMIT] [-A after] [-B before] {\n"
"\t\t-f |\n"
"\t\t-J inputfile |\n"
"\t\t[-t type] [-b bailiwick] {\n"
"\t\t\t-r OWNER[/TYPE[/BAILIWICK]] |\n"
"\t\t\t-n NAME[/TYPE] |\n"
"\t\t\t-i IP[/PFXLEN]\n"
"\t\t}\n"
"\t}\n"
"for -f, stdin must contain lines of the following forms:\n"
"\trrset/name/NAME[/TYPE[/BAILIWICK]]\n"
"\trdata/name/NAME[/TYPE]\n"
"\trdata/ip/ADDR[/PFXLEN]\n"
"for -f, output format will be determined by -p, using --\\n framing\n"
"for -J, input format is newline-separated JSON, as for -j output\n"
"for -A and -B, use abs. YYYY-MM-DD[ HH:MM:SS] "
		"or rel. %%dw%%dd%%dh%%dm%%ds format\n"
"use -j as a synonym for -p json.\n"
"use -s to sort in ascending order, or -S for descending order.\n"
"use -h to reliably display this helpful text.\n"
"use -c to get complete (vs. partial) time matching for -A and -B\n"
"\n"
"try   man %s   for a longer description\n",
		program_name, program_name);
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

/* my_exit -- free() the heap objects supplied as arguments, then exit.
 */
static __attribute__((noreturn)) void
my_exit(int code, ...) {
	va_list ap;
	void *p;

	/* our varargs are things to be free()'d. */
	va_start(ap, code);
	while (p = va_arg(ap, void *), p != NULL)
		free(p);
	va_end(ap);

	/* globals which may have been initialized, are to be free()'d. */
	DESTROY(key_header);
	DESTROY(api_key);
	DESTROY(api_prefix);
	DESTROY(dnsdb_server);

	/* writers and readers which are still known, must be free()'d. */
	while (writers != NULL)
		writer_fini(writers);

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	/* terminate process. */
	if (debuglev > 0)
		fprintf(stderr, "about to call exit(%d)\n", code);
	exit(code);
}

/* server_setup -- learn the server name and API key by various means.
 */
static void
server_setup(void) {
	read_configs();
	read_environ();
	if (api_prefix == NULL)
		api_prefix = strdup(default_prefix);
	if (asprintf(&key_header, "X-Api-Key: %s", api_key) < 0) {
		perror("asprintf");
		my_exit(1, NULL);
	}
}

/* read_configs -- try to find a config file in static path, then parse it.
 */
static void
read_configs(void) {
	const char * const *conf;
	char *cf;

	cf = NULL;
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
	}
	if (*conf != NULL) {
		char *cmd, *tok, *line;
		size_t n;
		FILE *f;
		int x;

		x = asprintf(&cmd,
			     ". %s;"
			     "echo apikey $APIKEY;"
			     "echo server $DNSDB_SERVER",
			     cf);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, NULL);
		}
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
		while (getline(&line, &n, f) > 0) {
			if (strchr(line, '\n') == NULL) {
				fprintf(stderr, "%s: line too long\n", cf);
				my_exit(1, cf, NULL);
			}
			if (debuglev > 0)
				fprintf(stderr, "conf line: %s", line);
			tok = strtok(line, "\040\012");
			if (tok != NULL && strcmp(tok, "apikey") == 0) {
				tok = strtok(NULL, "\040\012");
				if (tok != NULL)
					api_key = strdup(tok);
			} else if (tok != NULL && strcmp(tok, "server") == 0) {
				tok = strtok(NULL, "\040\012");
				if (tok != NULL)
					dnsdb_server = strdup(tok);
			} else {
				fprintf(stderr, "%s: line malformed\n", cf);
				my_exit(1, cf, NULL);
			}
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
			free(api_key);
		api_key = strdup(val);
		if (debuglev > 0)
			fprintf(stderr, "conf env api_key = '%s'\n", api_key);
	}
	val = getenv(env_dnsdb_server);
	if (val != NULL) {
		if (dnsdb_server != NULL)
			free(dnsdb_server);
		dnsdb_server = strdup(val);
		if (debuglev > 0)
			fprintf(stderr, "conf env dnsdb_server = '%s'\n",
				dnsdb_server);
	}
	if (api_key == NULL) {
		fprintf(stderr, "no API key given\n");
		my_exit(1, NULL);
	}
	if (dnsdb_server == NULL) {
		dnsdb_server = strdup(default_server);
		if (debuglev > 0)
			fprintf(stderr, "conf default dnsdb_server = '%s'\n",
				dnsdb_server);
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

		if (nl == NULL) {
			fprintf(stderr, "batch line too long: %s\n", command);
			continue;
		}
		*nl = '\0';
		if (debuglev > 0)
			fprintf(stderr, "do_batch(%s)\n", command);

		/* if not merging, start a writer here instead. */
		if (!merge)
			writer = writer_init(after, before);

		/* start one or two curl jobs based on this search. */
		query_launcher(command, writer, after, before);

		/* if merging, drain some jobs; else, drain all jobs. */
		if (merge) {
			io_engine(MAX_JOBS);
		} else {
			io_engine(0);
			writer_fini(writer);
			writer = NULL;
			fprintf(stdout, "--\n");
			fflush(stdout);
		}
	}
	DESTROY(command);
	
	/* if merging, run remaining jobs to completion, then finish up. */
	if (merge) {
		io_engine(0);
		writer_fini(writer);
	}
}

/* makepath -- make a RESTful URI that describes these search parameters
 */
static char *
makepath(mode_e mode, const char *name, const char *type,
	 const char *bailiwick, const char *length)
{
	char *command;
	int x;

	switch (mode) {
	case rdata_mode:
		if (type != NULL && bailiwick != NULL)
			x = asprintf(&command, "rrset/name/%s/%s/%s",
				     name, type, bailiwick);
		else if (type != NULL)
			x = asprintf(&command, "rrset/name/%s/%s",
				     name, type);
		else
			x = asprintf(&command, "rrset/name/%s",
				     name);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, NULL);
		}
		break;
	case name_mode:
		if (type != NULL)
			x = asprintf(&command, "rdata/name/%s/%s",
				     name, type);
		else
			x = asprintf(&command, "rdata/name/%s",
				     name);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, NULL);
		}
		break;
	case ip_mode:
		if (length != NULL)
			x = asprintf(&command, "rdata/ip/%s,%s",
				     name, length);
		else
			x = asprintf(&command, "rdata/ip/%s",
				     name);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, NULL);
		}
		break;
	case no_mode:
		/*FALLTHROUGH*/
	default:
		abort();
	}
	return (command);
}

/* makeurl -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 */
static char *
makeurl(const char *path) {
	char *ret;
	int x;

	switch (api_system) {
	case sys_dnsdb:
		x = asprintf(&ret, "%s%s/%s", dnsdb_server, api_prefix, path);
		if (x < 0) {
			perror("asprintf");
			ret = NULL;
		}
		break;
	default:
		abort();
	}
	return (ret);
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

/* dnsdb_query -- launch one or more libcurl jobs to fulfill this DNSDB query.
 */
static void
dnsdb_query(const char *command, u_long after, u_long before) {
	writer_t writer;

	if (debuglev > 0)
		fprintf(stderr, "dnsdb_query(%s)\n", command);

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

/* launch -- actually launch a libcurl job, given a command and time fences.
 */
static void
launch(const char *command, writer_t writer,
       u_long first_after, u_long first_before,
       u_long last_after, u_long last_before)
{
	reader_t reader;
	CURLMcode res;
	char sep;
	int x;

	reader = malloc(sizeof *reader);
	if (reader == NULL) {
		perror("malloc");
		my_exit(1, NULL);
	}
	memset(reader, 0, sizeof *reader);
	reader->writer = writer;
	reader->easy = curl_easy_init();
	if (reader->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		my_exit(1, reader, NULL);
	}

	reader->url = makeurl(command);
	if (reader->url == NULL)
		my_exit(1, reader, NULL);
	sep = '?';
	/* only say ?limit= if it was specified and we aren't sorting. if we
	 * are sorting, we'll implement this on the output of the sort.
	 */
	if (limit != 0 && sorted == no_sort) {
		char *tmp;

		x = asprintf(&tmp, "%s%c" "limit=%d", reader->url, sep, limit);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, reader->url, reader, NULL);
		}
		free(reader->url);
		reader->url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (first_after != 0) {
		char *tmp;

		x = asprintf(&tmp, "%s%c" "time_first_after=%lu",
			     reader->url, sep, (u_long)first_after);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, reader->url, reader, NULL);
		}
		free(reader->url);
		reader->url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (first_before != 0) {
		char *tmp;

		x = asprintf(&tmp, "%s%c" "time_first_before=%lu",
			     reader->url, sep, (u_long)first_before);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, reader->url, reader, NULL);
		}
		free(reader->url);
		reader->url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (last_after != 0) {
		char *tmp;

		x = asprintf(&tmp, "%s%c" "time_last_after=%lu",
			     reader->url, sep, (u_long)last_after);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, reader->url, reader, NULL);
		}
		free(reader->url);
		reader->url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (last_before != 0) {
		char *tmp;

		x = asprintf(&tmp, "%s%c" "time_last_before=%lu",
			     reader->url, sep, (u_long)last_before);
		if (x < 0) {
			perror("asprintf");
			my_exit(1, reader->url, reader, NULL);
		}
		free(reader->url);
		reader->url = tmp;
		tmp = NULL;
		sep = '&';
	}
	if (debuglev > 0)
		fprintf(stderr, "url [%s]\n", reader->url);

	curl_easy_setopt(reader->easy, CURLOPT_URL, reader->url);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	reader->hdrs = curl_slist_append(reader->hdrs, key_header);
	reader->hdrs = curl_slist_append(reader->hdrs, json_header);
	curl_easy_setopt(reader->easy, CURLOPT_HTTPHEADER, reader->hdrs);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEDATA, reader);
	reader->next = writer->readers;
	writer->readers = reader;
	reader = NULL;

	res = curl_multi_add_handle(multi, writer->readers->easy);
	if (res != CURLM_OK) {
		fprintf(stderr, "curl_multi_add_handle() failed: %s\n",
			curl_multi_strerror(res));
		writer_fini(writer);
		writer = NULL;
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
	free(reader);
}

/* ruminate_json -- process a json file from the filesys rather than the API.
 */
static void
ruminate_json(int json_fd, u_long after, u_long before) {
	reader_t reader;
	writer_t writer;
	char buf[65536];
	ssize_t len;

	writer = writer_init(after, before);
	reader = malloc(sizeof(struct reader));
	if (reader == NULL) {
		perror("malloc");
		my_exit(1, NULL);
	}
	memset(reader, 0, sizeof(struct reader));
	reader->writer = writer;
	writer->readers = reader;
	reader = NULL;
	while ((len = read(json_fd, buf, sizeof buf)) > 0) {
		writer_func(buf, 1, (size_t)len, writer->readers);
	}
	writer_fini(writer);
	writer = NULL;
}

/* writer_init -- instantiate a writer, which may involve forking a "sort".
 */
static writer_t
writer_init(u_long after, u_long before) {
	writer_t writer;

	writer = malloc(sizeof(struct writer));
	if (writer == NULL) {
		perror("malloc");
		my_exit(1, NULL);
	}
	memset(writer, 0, sizeof(struct writer));

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

		if (pipe(p1) < 0 || pipe(p2) < 0) {
			perror("pipe");
			my_exit(1, NULL);
		}
		if ((writer->sort_pid = fork()) < 0) {
			perror("fork");
			my_exit(1, NULL);
		}
		if (writer->sort_pid == 0) {
			char *sort_argv[5+MAX_KEYS], **sap;
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
			for (n = 0; n < nkeys; n++) {
				char *karg = NULL;
				int x = asprintf(&karg, "-k%d", keys[n]);

				if (x < 0) {
					perror("asprintf");
					_exit(1);
				}
				*sap++ = karg;
			}
			*sap++ = strdup("-n");
			*sap++ = strdup("-u");
			if (sorted == reverse_sort)
				*sap++ = strdup("-r");
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

/* writer_func -- process a block of json text, from filesys or API socket.
 */
static size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	reader_t reader = (reader_t) blob;
	size_t bytes = size * nmemb;
	u_long after, before;
	char *nl;

	if (debuglev > 2)
		fprintf(stderr, "writer_func(%d, %d): %d\n",
			(int)size, (int)nmemb, (int)bytes);

	reader->buf = realloc(reader->buf, reader->len + bytes);
	memcpy(reader->buf + reader->len, ptr, bytes);
	reader->len += bytes;

	after = reader->writer->after;
	before = reader->writer->before;

	while ((nl = memchr(reader->buf, '\n', reader->len)) != NULL) {
		size_t pre_len, post_len;
		struct dnsdb_tuple tup;
		const char *msg, *whynot;
		u_long first, last;

		if (reader_error(reader))
			return (0);
		pre_len = (size_t)(nl - reader->buf);

		msg = tuple_make(&tup, reader->buf, pre_len);
		if (msg) {
			puts(msg);
			goto more;
		}

		/* there are two sets of timestamps in a tuple. we prefer
		 * the on-the-wire times to the zone times, when possible.
		 */
		if (tup.time_first != 0 && tup.time_last != 0) {
			first = (u_long)tup.time_first;
			last = (u_long)tup.time_last;
		} else {
			first = (u_long)tup.zone_first;
			last = (u_long)tup.zone_last;
		}
		whynot = NULL;
		if (debuglev > 1)
			fprintf(stderr, "filtering-- ");

		/* time fencing can in some cases (-A & -B w/o -c) require
		 * asking the server for more than we really want, and so
		 * we have to winnow it down upon receipt. (see also -J.)
		 */
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
			/* POSIX sort is given three integers at the
			 * front of each line (first, last, count)
			 * which are accessed as -k1, -k2 or -k3 on the
			 * sort command line. we strip them off later
			 * when reading the result back. the reason
			 * for all this old-school code is to avoid
			 * having to store the full result in memory.
			 */
			fprintf(reader->writer->sort_stdin,
				"%lu %lu %lu %*.*s\n",
				(unsigned long)first,
				(unsigned long)last,
				(unsigned long)tup.count,
				(int)pre_len, (int)pre_len,
				reader->buf);
		} else {
			(*pres)(&tup, reader->buf, pre_len, stdout);
		}
		reader->writer->count++;
 next:
		tuple_unmake(&tup);
 more:
		post_len = (reader->len - pre_len) - 1;
		memmove(reader->buf, nl + 1, post_len);
		reader->len = post_len;
	}
	return (bytes);
}

/* writer_fini -- stop a writer's readers, and perhaps execute a "sort".
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

		/* display any error messages still lurking in buffers. */
		if (reader->buf != NULL) {
			if (reader_error(reader))
				reader->len = 0;
			DESTROY(reader->buf);
		}
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
			if (limit != 0 && count >= limit)
				continue;

			char *nl, *linep;
			const char *msg;
			struct dnsdb_tuple tup;

			if ((nl = strchr(line, '\n')) == NULL) {
				fprintf(stderr, "no \\n found in '%s'\n",
					line);
				continue;
			}
			linep = line;
			/* skip first, last, and count -- the sort keys. */
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
			msg = tuple_make(&tup, linep, (size_t)(nl - linep));
			if (msg != NULL) {
				puts(msg);
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
				count, limit);
		if (waitpid(writer->sort_pid, &status, 0) < 0) {
			perror("waitpid");
		} else {
			if (status != 0)
				fprintf(stderr, "sort exit status is %u\n",
					status);
		}
	}
	free(writer);
}

/* io_engine -- let libcurl run until there are few enough outstanding jobs.
 */
static void
io_engine(int jobs) {
	CURLMsg *msg;
	int still;

	/* let libcurl run while there are too many jobs remaining. */
	still = 0;
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > jobs)
		curl_multi_wait(multi, NULL, 0, 0, NULL);

	/* pull out all the response codes, die suddenly on any failure.. */
	still = 0;
	while ((msg = curl_multi_info_read(multi, &still)) != NULL) {
		long rcode;
		char *url;

		if (msg->msg != CURLMSG_DONE)
			continue;
		curl_easy_getinfo(msg->easy_handle,
				  CURLINFO_RESPONSE_CODE, &rcode);
		if (rcode != 200) {
			curl_easy_getinfo(msg->easy_handle,
					  CURLINFO_EFFECTIVE_URL, &url);
			fprintf(stderr, "libcurl: %ld (%s)\n", rcode, url);
			if (rcode == 404)
				fprintf(stderr, "please note: 404 usually "
					"just means that no records matched "
					"the search\n");
		}
	}
}

/* reader_error -- if the response body isn't a json blob, print as error.
 *
 * design critique: this is incredibly fragile and bogus.
 */
static int
reader_error(reader_t reader) {
	if (reader->buf[0] != '\0' && reader->buf[0] != '{') {
		fprintf(stderr, "API: %-*.*s",
		       (int)reader->len, (int)reader->len, reader->buf);
		reader->buf[0] = '\0';
		reader->len = 0;
		return (1);
	}
	return (0);
}

/* present_dns -- render one dnsdb tuple in "dig" style ascii text.
 */
static void
present_dns(const dnsdb_tuple_t tup,
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
		prefix = ";";
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

/* present_json -- render one DNSDB tuple as newline-separated JSON.
 */
static void
present_json(const dnsdb_tuple_t tup __attribute__ ((unused)),
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
present_csv(const dnsdb_tuple_t tup,
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
present_csv_line(const dnsdb_tuple_t tup,
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

/* tuple_make -- create one DNSDB tuple object out of a JSON object.
 */
static const char *
tuple_make(dnsdb_tuple_t tup, char *buf, size_t len) {
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

	/* Count and Bailiwick. */
	tup->obj.count = json_object_get(tup->obj.main, "count");
	if (tup->obj.count != NULL) {
		if (!json_is_integer(tup->obj.count)) {
			msg = "count must be an integer";
			goto ouch;
		}
		tup->count = json_integer_value(tup->obj.count);
	}
	tup->obj.bailiwick = json_object_get(tup->obj.main, "bailiwick");
	if (tup->obj.bailiwick != NULL) {
		if (!json_is_string(tup->obj.bailiwick)) {
			msg = "bailiwick must be a string";
			goto ouch;
		}
		tup->bailiwick = json_string_value(tup->obj.bailiwick);
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
tuple_unmake(dnsdb_tuple_t tup) {
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
		time_t t = (time_t)x;
		struct tm *y = gmtime(&t);
		char z[99];

		strftime(z, sizeof z, "%F %T", y);
		fputs(z, outf);
	}
}

/* time_get -- parse and return one (possibly relative) timestamp.
 */
static int
time_get(const char *src, u_long *dst) {
	struct tm tt;
	u_long t;
	char *ep;

	memset(&tt, 0, sizeof tt);
	if (((ep = strptime(src, "%F %T", &tt)) != NULL && *ep == '\0') ||
	    ((ep = strptime(src, "%F", &tt)) != NULL && *ep == '\0'))
	{
		*dst = (u_long)(mktime(&tt) - here.tz_minuteswest);
		return (1);
	}
	t = strtoul(src, &ep, 10);
	if (*src != '\0' && *ep == '\0') {
		*dst = t;
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
	free(*src);
	*src = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
}
