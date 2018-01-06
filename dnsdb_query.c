/* Copyright (C) 2014-2018, Farsight Security, Inc. No rights reserved. */

/* External. */

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
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

/* Internal. */

#define DNSDB_SERVER "https://api.dnsdb.info"

struct dnsdb_json {
	json_t		*main,
			*time_first, *time_last, *zone_first, *zone_last,
			*bailiwick, *rrname, *rrtype, *rdata,
			*count;
};

struct dnsdb_tuple {
	struct dnsdb_json  obj;
	time_t		time_first, time_last, zone_first, zone_last;
	const char	*bailiwick, *rrname, *rrtype, *rdata;
	json_int_t	count;
};
typedef struct dnsdb_tuple *dnsdb_tuple_t;

typedef void (*present_t)(const dnsdb_tuple_t, const char *, size_t, FILE *);

struct reader {
	struct reader		*next;
	CURL			*easy;
	struct curl_slist	*hdrs;
	char			*url;
	char			*buf;
	size_t			len;
};
typedef struct reader *reader_t;

struct writer {
	FILE			*sort_stdin;
	FILE			*sort_stdout;
	pid_t			sort_pid;
};

/* Constant. */

static const char * const conf_files[] = {
	"~/.isc-dnsdb-query.conf",
	"~/.dnsdb-query.conf",
	"/etc/isc-dnsdb-query.conf",
	"/etc/dnsdb-query.conf",
	NULL
};

static const char json_header[] = "Accept: application/json";

/* Forward. */

static __attribute__((noreturn)) void usage(const char *);
static __attribute__((noreturn)) void my_exit(int, ...);
static void read_configs(void);
static void make_curl(void);
static void unmake_curl(void);
static void dnsdb_query(const char *);
static void launch(const char *, time_t, time_t, time_t, time_t);
static void all_readers(void);
static void rendezvous(reader_t);
static void present_json(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_dns(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_csv(const dnsdb_tuple_t, const char *, size_t, FILE *);
static void present_csv_line(const dnsdb_tuple_t, const char *, FILE *);
static const char *tuple_make(dnsdb_tuple_t, char *, size_t);
static void tuple_unmake(dnsdb_tuple_t);
static int timecmp(time_t, time_t);
static void writer_init(void);
static size_t writer_func(char *ptr, size_t size, size_t nmemb, void *blob);
static void writer_fini(void);
static int reader_error(reader_t);
static void time_print(time_t x, FILE *);
static int time_get(const char *src, time_t *dst);
static void escape(char **);

/* Private. */

static const char *program_name = NULL;
static char *api_key = NULL;
static char *key_header = NULL;
static char *dnsdb_server = NULL;
static int batch = 0;
static int dry_run = 0;
static int debug = 0;
static enum { no_sort, normal_sort, reverse_sort } sorted = no_sort;
static enum { filter_none, filter_overlap } filter = filter_none;
static int curl_cleanup_needed = 0;
static present_t pres = present_dns;
static reader_t readers = NULL;
static time_t after = 0;
static time_t before = 0;
static int limit = 0;
static int loose = 0;
static CURLM *multi = NULL;
static time_t startup;
static struct writer writer;

/* Public. */

int
main(int argc, char *argv[]) {
	enum { no_mode = 0, rdata_mode, name_mode, ip_mode } mode = no_mode;
	char *name = NULL, *type = NULL, *bailiwick = NULL, *length = NULL;
	const char *val;
	int ch;

	program_name = strrchr(argv[0], '/');
	startup = time(NULL);
	if (program_name == NULL)
		program_name = argv[0];
	else
		program_name++;

	while ((ch = getopt(argc, argv, "A:B:r:n:i:l:p:t:b:vdjfsShL")) != -1) {
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
					type = strndup(p + 1, q - p - 1);
				} else {
					type = strdup(p + 1);
				}
				name = strndup(optarg, p - optarg);
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
				name = strndup(optarg, p - optarg);
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
				name = strndup(optarg, p - optarg);
				length = strdup(p + 1);
			} else {
				name = strdup(optarg);
			}
			break;
		    }
		case 'l':
			limit = atoi(optarg);
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
			if (batch)
				usage("can't mix -t with -f");
			if (type != NULL)
				free(type);
			type = strdup(optarg);
			break;
		case 'b':
			if (batch)
				usage("can't mix -b with -f");
			if (bailiwick != NULL)
				free(bailiwick);
			bailiwick = strdup(optarg);
			break;
		case 'v':
			dry_run++;
			break;
		case 'd':
			debug++;
			break;
		case 'j':
			pres = present_json;
			break;
		case 'f':
			batch++;
			break;
		case 's':
			sorted = normal_sort;
			break;
		case 'S':
			sorted = reverse_sort;
			break;
		case 'L':
			loose++;
			break;
		case 'h':
			usage(NULL);
			break;
		default:
			usage("unrecognized option");
		}
	}
	argc -= optind;
	argv += optind;
	if (name != NULL)
		escape(&name);
	if (type != NULL)
		escape(&type);
	if (bailiwick != NULL)
		escape(&bailiwick);
	if (length != NULL)
		escape(&length);
	if (debug > 0) {
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
	}

	read_configs();
	val = getenv("DNSDB_API_KEY");
	if (val != NULL) {
		if (api_key != NULL)
			free(api_key);
		api_key = strdup(val);
		if (debug > 0)
			fprintf(stderr, "conf env api_key = '%s'\n", api_key);
	}
	val = getenv("DNSDB_SERVER");
	if (val != NULL) {
		if (dnsdb_server != NULL)
			free(dnsdb_server);
		dnsdb_server = strdup(val);
		if (debug > 0)
			fprintf(stderr, "conf env dnsdb_server = '%s'\n",
				dnsdb_server);
	}
	if (api_key == NULL) {
		fprintf(stderr, "no API key given\n");
		my_exit(1, NULL);
	}
	if (dnsdb_server == NULL) {
		dnsdb_server = strdup(DNSDB_SERVER);
		if (debug > 0)
			fprintf(stderr, "conf default dnsdb_server = '%s'\n",
				dnsdb_server);
	}
	if (asprintf(&key_header, "X-Api-Key: %s", api_key) < 0) {
		perror("asprintf");
		my_exit(1, NULL);
	}

	if (after != 0 && before != 0) {
		if (after > 0 && before > 0 && after > before) {
			fprintf(stderr,
				"-A -B requires after <= before\n");
			my_exit(1, NULL);
		}
		if (loose && sorted == no_sort) {
			fprintf(stderr,
				"-A -B -L requires -s or -S for dedup\n");
			my_exit(1, NULL);
		}
	}

	if (batch) {
		char command[1000];

		if (mode != no_mode)
			usage("can't mix -n, -r, or -i with -f");
		make_curl();
		while (fgets(command, sizeof command, stdin) != NULL) {
			char *nl = strchr(command, '\n');

			if (nl == NULL) {
				fprintf(stderr, "batch line too long: %s\n",
					command);
				continue;
			}
			*nl = '\0';
			dnsdb_query(command);
			fprintf(stdout, "--\n");
			fflush(stdout);
		}
		unmake_curl();
	} else {
		char *command;

		switch (mode) {
			int x;
		case no_mode:
			usage("must specify -r, -n, or -i unless -f is used");
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
		default:
			abort();
		}
		if (name != NULL) {
			free(name);
			name = NULL;
		}
		if (type != NULL) {
			free(type);
			type = NULL;
		}
		if (bailiwick != NULL) {
			free(bailiwick);
			bailiwick = NULL;
		}
		make_curl();
		dnsdb_query(command);
		free(command);
		command = NULL;
		unmake_curl();
	}
	my_exit(0, NULL);
}

/* Private. */

static __attribute__((noreturn)) void usage(const char *error) {
	if (error != NULL)
		fprintf(stderr, "error: %s\n", error);
	fprintf(stderr,
"usage: %s [-vdjsSh] [-p dns|json|csv] [-l LIMIT] [-A after] [-B before] {\n"
"\t-f |\n"
"\t[-t type] [-b bailiwick] {\n"
"\t\t-r OWNER[/TYPE[/BAILIWICK]] |\n"
"\t\t-n NAME[/TYPE] |\n"
"\t\t-i IP[/PFXLEN]\n"
"\t}\n"
"}\n"
"for -f, stdin must contain lines of the following forms:\n"
"\trrset/name/NAME[/TYPE[/BAILIWICK]]\n"
"\trdata/name/NAME[/TYPE]\n"
"\trdata/ip/ADDR[/PFXLEN]\n"
"for -f, output format will be determined by -p, using --\\n framing\n"
"for -A and -B, use abs. YYYY-DD-MM[ HH:MM:SS] "
"or rel. %%dw%%dd%%dh%%dm%%ds format\n",
		program_name);
	my_exit(1, NULL);
}

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
	if (key_header != NULL) {
		free(key_header);
		key_header = NULL;
	}
	if (api_key != NULL) {
		free(api_key);
		api_key = NULL;
	}
	if (dnsdb_server != NULL) {
		free(dnsdb_server);
		dnsdb_server = NULL;
	}

	/* readers which are still known, must be free()'d. */
	all_readers();

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	exit(code);
}

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
			if (debug > 0)
				fprintf(stderr, "conf found: '%s'\n", cf);
			break;
		}
	}
	if (*conf != NULL) {
		char *cmd, *tok, line[1000];
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
		if (debug > 0)
			fprintf(stderr, "conf cmd = '%s'\n", cmd);
		free(cmd);
		cmd = NULL;
		while (fgets(line, sizeof line, f) != NULL) {
			if (strchr(line, '\n') == NULL) {
				fprintf(stderr, "%s: line too long\n", cf);
				my_exit(1, cf, NULL);
			}
			if (debug > 0)
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
		pclose(f);
	}
	free(cf);
	cf = NULL;
}

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

static void
dnsdb_query(const char *command) {
	CURLMsg *msg;
	int still;

	if (debug > 0)
		fprintf(stderr, "dnsdb_query(%s)\n", command);

	/* start a writer, which might be format functions, or POSIX sort. */
	writer_init();

	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (after != 0 && before != 0) {
		if (!loose) {
			/* each db tuple must be enveloped by time fence. */
			launch(command, after, 0, 0, before);
		} else {
			/* we need tuples that end after fence start... */
			launch(command, 0, 0, after, 0);
			/* ...and that begin before the time fence end. */
			launch(command, 0, before, 0, 0);
			/* and we will filter in reader_func() to
			 * select only those tuples which either:
			 * ...(start within), or (end within), or
			 * ...(start before and end after).
			 */
			filter = filter_overlap;
		}
	} else if (after != 0) {
		if (!loose) {
			/* each db tuple must begin after the fence-start. */
			launch(command, after, 0, 0, 0);
		} else {
			/* each db tuple must end after the fence-start. */
			launch(command, 0, 0, after, 0);
		}
	} else if (before != 0) {
		if (!loose) {
			/* each db tuple must end before the fence-end. */
			launch(command, 0, 0, 0, before);
		} else {
			/* each db tuple must begin before the fence-end. */
			launch(command, 0, before, 0, 0);
		}
	} else {
		/* no time fencing. */
		launch(command, 0, 0, 0, 0);
	}
	
	/* let libcurl run until there are no jobs remaining. */
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > 0) {
		curl_multi_wait(multi, NULL, 0, 0, NULL);
	}
	/* pull out all the response codes, die suddenly on any failure.. */
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
		}
	}
	/* shut down and reclaim all the curl jobs. */
	all_readers();

	/* stop the writer, which might involve reading POSIX sort's output. */
	writer_fini();
}

static void
launch(const char *command,
       time_t first_after, time_t first_before,
       time_t last_after, time_t last_before)
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
	reader->easy = curl_easy_init();
	if (reader->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		my_exit(1, reader, NULL);
	}

	x = asprintf(&reader->url, "%s/lookup/%s", dnsdb_server, command);
	if (x < 0) {
		perror("asprintf");
		my_exit(1, reader, NULL);
	}
	sep = '?';
	if (limit != 0) {
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
	if (debug > 0)
		fprintf(stderr, "url [%s]\n", reader->url);

	curl_easy_setopt(reader->easy, CURLOPT_URL, reader->url);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	reader->hdrs = curl_slist_append(reader->hdrs, key_header);
	reader->hdrs = curl_slist_append(reader->hdrs, json_header);
	curl_easy_setopt(reader->easy, CURLOPT_HTTPHEADER, reader->hdrs);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEDATA, reader);

	res = curl_multi_add_handle(multi, reader->easy);
	if (res != CURLM_OK) {
		fprintf(stderr, "curl_multi_add_handle() failed: %s\n",
			curl_multi_strerror(res));
		writer_fini();
		rendezvous(reader);
		my_exit(1, NULL);
	}
	reader->next = readers;
	readers = reader;
}

static void
all_readers(void) {
	while (readers != NULL) {
		reader_t next = readers->next;
		rendezvous(readers);
		readers = next;
	}
}

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
	if (reader->url != NULL) {
		free(reader->url);
		reader->url = NULL;
	}
	free(reader);
}

static void
writer_init(void) {
	memset(&writer, 0, sizeof writer);

	if (sorted != no_sort) {
		/* sorting involves a subprocess (POSIX /usr/bin/sort),
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
		if ((writer.sort_pid = fork()) < 0) {
			perror("fork");
			my_exit(1, NULL);
		}
		if (writer.sort_pid == 0) {
			char *sort_argv[7], **sap;

			if (dup2(p1[0], STDIN_FILENO) < 0 ||
			    dup2(p2[1], STDOUT_FILENO) < 0) {
				perror("dup2");
				_exit(1);
			}
			close(p1[0]);
			close(p1[1]);
			close(p2[0]);
			close(p2[1]);
			sap = sort_argv;
			*sap++ = strdup("sort");
			*sap++ = strdup("-k1");
			*sap++ = strdup("-k2");
			*sap++ = strdup("-n");
			*sap++ = strdup("-u");
			if (sorted == reverse_sort)
				*sap++ = strdup("-r");
			*sap++ = NULL;
			putenv(strdup("LC_ALL=C"));
			execve("/usr/bin/sort", sort_argv, environ);
			perror("execve");
			for (sap = sort_argv; *sap != NULL; sap++) {
				free(*sap);
				*sap = NULL;
			}
			_exit(1);
		}
		close(p1[0]);
		writer.sort_stdin = fdopen(p1[1], "w");
		writer.sort_stdout = fdopen(p2[0], "r");
		close(p2[1]);
	}
}

/* this is the libcurl callback, which is not line-oriented, so we have to
 * do our own parsing here to pull newline-delimited-json out of the stream
 * and process it one object at a time.
 */
static size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	reader_t reader = (reader_t) blob;
	size_t bytes = size * nmemb;
	char *nl;

	if (debug > 2)
		fprintf(stderr, "writer(%d, %d): %d\n",
			(int)size, (int)nmemb, (int)bytes);

	reader->buf = realloc(reader->buf, reader->len + bytes);
	memcpy(reader->buf + reader->len, ptr, bytes);
	reader->len += bytes;

	while ((nl = memchr(reader->buf, '\n', reader->len)) != NULL) {
		size_t pre_len, post_len;
		time_t first, last;
		const char *msg;
		struct dnsdb_tuple tup;

		if (reader_error(reader))
			return (0);
		pre_len = nl - reader->buf;

		msg = tuple_make(&tup, reader->buf, pre_len);
		if (msg) {
			puts(msg);
			goto next;
		}

		/* there are two sets of timestamps in a tuple. we prefer
		 * the on-the-wire times to the zone times, when possible.
		 */
		if (tup.time_first != 0 && tup.time_last != 0) {
			first = tup.time_first;
			last = tup.time_last;
		} else {
			first = tup.zone_first;
			last = tup.zone_last;
		}

		/* time fencing can in some cases (-A + -B + -L) require
		 * asking the server for more than we really want, and so
		 * we have to winnow it down upon receipt.
		 */
		if (filter == filter_overlap && after != 0 && before != 0) {
			const char *why;

			/* reduce results to just things that either:
			 * ...(start within), or (end within), or
			 * ...(start before and end after).
			 */
			int first_vs_before = timecmp(first, before);
			int first_vs_after = timecmp(first, after);
			int last_vs_before = timecmp(last, before);
			int last_vs_after = timecmp(last, after);
			if (debug > 1) {
				fprintf(stderr, "filtering-- "
					"FvB %d FvA %d LvB %d LvA %d: ",
					first_vs_before, first_vs_after,
					last_vs_before, last_vs_after);
			}
			why = NULL;
			if (first_vs_after >= 0 && first_vs_before <= 0)
				why = "F within A..B";
			if (last_vs_after >= 0 && last_vs_before <= 0)
				why = "L within A..B";
			if (first_vs_after <= 0 && last_vs_before >= 0)
				why = "F..L contains A..B";
			if (why != NULL) {
				if (debug > 1)
					fprintf(stderr, "selected! %s\n", why);
				if (debug > 2) {
					fputs("\tF..L =", stderr);
					time_print(first, stderr);
					fputs(" .. ", stderr);
					time_print(last, stderr);
					fputc('\n', stderr);

					fputs("\tA..B =", stderr);
					time_print(after, stderr);
					fputs(" .. ", stderr);
					time_print(before, stderr);
					fputc('\n', stderr);
				}
			} else {
				if (debug > 1)
					fprintf(stderr, "skipped.\n");
				goto next;
			}
		}

		if (sorted != no_sort) {
			/* POSIX sort is given two large integers at
			 * the front of each line (time{first,last})
			 * which are accessed as -k1 and -k2 on the
			 * sort command line. we strip them off later
			 * when reading the result back. the reason
			 * for all this old-school code is to avoid
			 * having to store the full result in memory.
			 */
			fprintf(writer.sort_stdin, "%lu %lu %*.*s\n",
				(unsigned long)first,
				(unsigned long)last,
				(int)pre_len, (int)pre_len,
				reader->buf);
		} else {
			(*pres)(&tup, reader->buf, pre_len, stdout);
		}
 next:
		tuple_unmake(&tup);
		post_len = (reader->len - pre_len) - 1;
		memmove(reader->buf, nl + 1, post_len);
		reader->len = post_len;
	}
	return (bytes);
}

static void
writer_fini(void) {
	reader_t reader;

	for (reader = readers; reader != NULL; reader = reader->next) {
		if (reader->buf != NULL) {
			(void) reader_error(reader);
			free(reader->buf);
			reader->buf = NULL;
		}
		if (reader->len != 0) {
			fprintf(stderr, "stranding %d octets!\n",
				(int)reader->len);
			reader->len = 0;
		}
	}
	if (sorted != no_sort) {
		char line[65536];
		int status;

		/* when sorting, there has been no output yet. gather the
		 * intermediate representation from the POSIX sort stdout,
		 * skip over the sort keys we added earlier, and process.
		 */
		fclose(writer.sort_stdin);
		while (fgets(line, sizeof line, writer.sort_stdout) != NULL) {
			char *nl, *linep;
			const char *msg;
			struct dnsdb_tuple tup;

			if ((nl = strchr(line, '\n')) == NULL) {
				fprintf(stderr, "no \\n found in '%s'\n",
					line);
				continue;
			}
			linep = line;
			/* skip time_first and time_last -- the sort keys. */
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
			msg = tuple_make(&tup, linep, nl - linep);
			if (msg != NULL) {
				puts(msg);
				continue;
			}
			(*pres)(&tup, linep, nl - linep, stdout);
			tuple_unmake(&tup);
		}
		fclose(writer.sort_stdout);
		if (waitpid(writer.sort_pid, &status, 0) < 0) {
			perror("waitpid");
		} else {
			if (status != 0)
				fprintf(stderr, "sort exit status is %u\n",
					status);
		}
	}
	memset(&writer, 0, sizeof writer);
}

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

static void
present_dns(const dnsdb_tuple_t tup,
	    const char *jsonbuf __attribute__ ((unused)),
	    size_t jsonlen __attribute__ ((unused)),
	    FILE *outf)
{
	int pflag, ppflag;
	const char *prefix;

	ppflag = 0;

	/* Timestamps. */
	if (tup->obj.time_first != NULL && tup->obj.time_last != NULL) {
		fputs(";; record times: ", outf);
		time_print(tup->time_first, outf);
		fputs(" .. ", outf);
		time_print(tup->time_last, outf);
		putc('\n', outf);
		ppflag++;
	}
	if (tup->obj.zone_first != NULL && tup->obj.zone_last != NULL) {
		fputs(";;   zone times: ", outf);
		time_print(tup->zone_first, outf);
		fputs(" .. ", outf);
		time_print(tup->zone_last, outf);
		putc('\n', outf);
		ppflag++;
	}

	/* Count and Bailiwick. */
	prefix = ";;";
	pflag = 0;
	if (tup->obj.count != NULL) {
		fprintf(outf, "%s count: %lld", prefix, (long long)tup->count);
		prefix = ";";
		pflag++;
		ppflag++;
	}
	if (tup->obj.bailiwick != NULL) {
		fprintf(outf, "%s bailiwick: %s", prefix, tup->bailiwick);
		prefix = ";";
		pflag++;
		ppflag++;
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
			ppflag++;
		}
	} else {
		fprintf(outf, "%s  %s  %s\n",
			tup->rrname, tup->rrtype, tup->rdata);
		ppflag++;
	}

	/* Cleanup. */
	if (ppflag)
		putc('\n', outf);
}

static void
present_json(const dnsdb_tuple_t tup __attribute__ ((unused)),
	     const char *jsonbuf,
	     size_t jsonlen,
	     FILE *outf)
{
	fwrite(jsonbuf, 1, jsonlen, outf);
	putc('\n', outf);
}

static void
present_csv(const dnsdb_tuple_t tup,
	    const char *jsonbuf __attribute__ ((unused)),
	    size_t jsonlen __attribute__ ((unused)),
	    FILE *outf)
{
	static int csv_headerp = 0;

	if (!csv_headerp) {
		fprintf(outf,
			"time_first,time_last,zone_first,zone_last,"
			"count,bailiwick,"
			"rrname,rrtype,rdata\n");
		csv_headerp = 1;
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

static const char *
tuple_make(dnsdb_tuple_t tup, char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

	memset(tup, 0, sizeof *tup);
	if (debug > 2)
		fprintf(stderr, "[%d] '%-*.*s'\n",
			(int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%d:%d: %s %s\n",
		       error.line, error.column,
		       error.text, error.source);
		abort();
	}
	if (debug > 3) {
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
		tup->zone_first = (time_t)
			json_integer_value(tup->obj.zone_first);
	}
	tup->obj.zone_last = json_object_get(tup->obj.main, "zone_time_last");
	if (tup->obj.zone_last != NULL) {
		if (!json_is_integer(tup->obj.zone_last)) {
			msg = "zone_time_last must be an integer";
			goto ouch;
		}
		tup->zone_last = (time_t)
			json_integer_value(tup->obj.zone_last);
	}
	tup->obj.time_first = json_object_get(tup->obj.main, "time_first");
	if (tup->obj.time_first != NULL) {
		if (!json_is_integer(tup->obj.time_first)) {
			msg = "time_first must be an integer";
			goto ouch;
		}
		tup->time_first = (time_t)
			json_integer_value(tup->obj.time_first);
	}
	tup->obj.time_last = json_object_get(tup->obj.main, "time_last");
	if (tup->obj.time_last != NULL) {
		if (!json_is_integer(tup->obj.time_last)) {
			msg = "time_last must be an integer";
			goto ouch;
		}
		tup->time_last = (time_t)
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

static void
tuple_unmake(dnsdb_tuple_t tup) {
	json_decref(tup->obj.main);
	if (debug > 0)
		memset(tup, 0x5a, sizeof *tup);
	else
		memset(tup, 0, sizeof *tup);
}

static time_t
abstime(time_t t) {
	if (t < 0)
		t += startup;
	return (t);
}

static int
timecmp(time_t a, time_t b) {
	time_t abs_a = abstime(a), abs_b = abstime(b);

	if (abs_a < abs_b)
		return (-1);
	if (abs_a > abs_b)
		return (1);
	return (0);
}

static void
time_print(time_t x, FILE *outf) {
	if (x < 0) {
		/* should maybe be able to reverse the ns_ttl encoding? */
		fprintf(outf, "%ld", (long)x);
	} else {
		struct tm *y = gmtime(&x);
		char z[99];

		strftime(z, sizeof z, "%F %T", y);
		fputs(z, outf);
	}
}

static int
time_get(const char *src, time_t *dst) {
	struct tm tt;
	u_long t;
	char *ep;

	memset(&tt, 0, sizeof tt);
	if (((ep = strptime(src, "%F %T", &tt)) != NULL && *ep == '\0') ||
	    ((ep = strptime(src, "%F", &tt)) != NULL && *ep == '\0'))
	{
		*dst = (u_long) mktime(&tt) - timezone;
		return (1);
	}
	t = strtoul(src, &ep, 10);
	if (*src != '\0' && *ep == '\0') {
		*dst = (time_t) t;
		return (1);
	}
	if (ns_parse_ttl(src, &t) == 0) {
		*dst = (time_t) (((u_long) time(NULL)) - t);
		return (1);
	}
	return (0);
}

static void
escape(char **src) {
	char *escaped;

	escaped = curl_escape(*src, strlen(*src));
	if (escaped == NULL) {
		fprintf(stderr, "curl_escape(%s) failed\n", *src);
		my_exit(1, NULL);
	}
	free(*src);
	*src = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
}
