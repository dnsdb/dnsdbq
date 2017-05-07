/* Copyright (C) 2014-2015, Farsight Security, Inc. No rights reserved. */

/***************************************************************************
 *
 * Portions Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/ 

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

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/* Internal. */

#define DNSDB_SERVER "https://api.dnsdb.info"

struct dnsdb_crack {
	struct {
		json_t *main, *time_first, *time_last, *zone_first, *zone_last,
			*count, *bailiwick, *rrname, *rrtype, *rdata;
	} obj;
	time_t time_first, time_last, zone_first, zone_last;
	const char *bailiwick, *rrname, *rrtype, *rdata;
	json_int_t count;
};

typedef void (*present)(const struct dnsdb_crack *, FILE *);

static const char * const conf_files[] = {
	"~/.isc-dnsdb-query.conf",
	"~/.dnsdb-query.conf",
	"/etc/isc-dnsdb-query.conf",
	"/etc/dnsdb-query.conf",
	NULL
};

static const char *program_name = NULL;
static char *api_key = NULL;
static char *dnsdb_server = NULL;
static int filter = 0;
static int verbose = 0;
static int debug = 0;
static enum { sort_not, sort_normal, sort_reverse } sorted = sort_not;
/* Forward. */

static void usage(const char *error)  __attribute__((__noreturn__));
static void read_configs(void);
static void dnsdb_query(const char *command, int limit, present,
			time_t, time_t);
static void present_dns(const struct dnsdb_crack *, FILE *);
static void present_csv(const struct dnsdb_crack *, FILE *);
static void present_csv_line(const struct dnsdb_crack *, const char *, FILE *);
static const char *dnsdb_crack_new(struct dnsdb_crack *, char *, size_t);
static void dnsdb_crack_destroy(struct dnsdb_crack *);
static void dnsdb_writer_init(void);
static size_t dnsdb_writer(char *ptr, size_t size, size_t nmemb, void *blob);
static void dnsdb_writer_fini(present);
static int dnsdb_writer_error(void);
static void time_print(time_t x, int, FILE *);
static int time_get(const char *src, time_t *dst);

/* Public. */

int
main(int argc, char *argv[]) {
	char *name = NULL, *type = NULL, *bailiwick = NULL, *length = NULL;
	enum { no_mode = 0, rdata_mode, name_mode, ip_mode } mode = no_mode;
	time_t after = 0, before = 0;
	present pres = present_dns;
	int ch, limit = 0;
	const char *val;

	program_name = strrchr(argv[0], '/');
	if (program_name == NULL)
		program_name = argv[0];
	else
		program_name++;

	while ((ch = getopt(argc, argv, "A:B:r:n:i:l:p:t:b:vdjfsSh")) != -1) {
		switch (ch) {
		case 'A':
			if (!time_get(optarg, &after)) {
				fprintf(stderr, "bad -A timestamp: '%s'\n",
					optarg);
				exit(1);
			}
			break;
		case 'B':
			if (!time_get(optarg, &before)) {
				fprintf(stderr, "bad -B timestamp: '%s'\n",
					optarg);
				exit(1);
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
			if (length == NULL)
				p = strchr(optarg, '/');
			else
				p = NULL;
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
				pres = NULL;
			else if (strcmp(optarg, "dns") == 0)
				pres = present_dns;
			else if (strcmp(optarg, "csv") == 0)
				pres = present_csv;
			else
				usage("-p must specify json, dns, or csv");
			break;
		case 't':
			if (filter)
				usage("can't mix -t with -f");
			if (type != NULL)
				free(type);
			type = strdup(optarg);
			break;
		case 'b':
			if (filter)
				usage("can't mix -b with -f");
			if (bailiwick != NULL)
				free(bailiwick);
			bailiwick = strdup(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			debug++;
			break;
		case 'j':
			pres = NULL;
			break;
		case 'f':
			filter++;
			break;
		case 's':
			sorted = sort_normal;
			break;
		case 'S':
			sorted = sort_reverse;
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

	if (debug && after != 0) {
		fprintf(stderr, "after =  ");
		time_print(after, FALSE, stderr);
		putc('\n', stderr);
	}
	if (debug && before != 0) {
		fprintf(stderr, "before = ");
		time_print(before, FALSE, stderr);
		putc('\n', stderr);
	}

	read_configs();
	val = getenv("DNSDB_API_KEY");
	if (val != NULL) {
		if (api_key != NULL)
			free(api_key);
		api_key = strdup(val);
		if (debug)
			fprintf(stderr, "conf env api_key = '%s'\n", api_key);
	}
	val = getenv("DNSDB_SERVER");
	if (val != NULL) {
		if (dnsdb_server != NULL)
			free(dnsdb_server);
		dnsdb_server = strdup(val);
		if (debug)
			fprintf(stderr, "conf env dnsdb_server = '%s'\n",
				dnsdb_server);
	}
	if (api_key == NULL) {
		fprintf(stderr, "no API key given\n");
		exit(1);
	}
	if (dnsdb_server == NULL) {
		dnsdb_server = strdup(DNSDB_SERVER);
		if (debug)
			fprintf(stderr, "conf default dnsdb_server = '%s'\n",
				dnsdb_server);
	}

	if (filter) {
		char command[1000];

		if (mode != no_mode)
			usage("can't mix -n, -r, or -i with -f");
		while (fgets(command, sizeof command, stdin) != NULL) {
			char *nl = strrchr(command, '\n');

			if (nl != NULL)
				*nl = '\0';
			dnsdb_query(command, limit, pres, after, before);
			fprintf(stdout, "--\n");
			fflush(stdout);
		}
	} else {
		char *command;

		if (debug) {
			if (name != NULL)
				fprintf(stderr, "name = '%s'\n", name);
			if (type != NULL)
				fprintf(stderr, "type = '%s'\n", type);
			if (bailiwick != NULL)
				fprintf(stderr, "bailiwick = '%s'\n",
					bailiwick);
			if (length != NULL)
				fprintf(stderr, "length = '%s'\n", length);
		}
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
				exit(1);
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
				exit(1);
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
				exit(1);
			}
			break;
		default:
			abort();
		}
		if (name != NULL)
			free(name);
		if (type != NULL)
			free(type);
		if (bailiwick != NULL)
			free(bailiwick);
		dnsdb_query(command, limit, pres, after, before);
		free(command);
	}
	free(api_key);
	free(dnsdb_server);
	return (0);
}

/* Private. */

static void usage(const char *error) {
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
"for -A and -B, use abs. YYYY-DD-MM[ HH:MM:SS] or rel. %%dw%%dd%%dh%%dm%%ds format\n",
		program_name);
	exit(1);
}

static void
read_configs(void) {
	const char * const *conf;
	const char *cf;

	cf = NULL;
	for (conf = conf_files; *conf != NULL; conf++) {
		wordexp_t we;

		wordexp(*conf, &we, WRDE_NOCMD);
		cf = strdup(we.we_wordv[0]);
		wordfree(&we);
		if (access(cf, R_OK) == 0) {
			if (debug)
				fprintf(stderr, "conf found: '%s'\n", cf);
			break;
		}
	}
	if (*conf != NULL) {
		char *cmd, *tok, line[1000];
		FILE *f;

		(void) asprintf(&cmd,
				". %s;"
				"echo apikey $APIKEY;"
				"echo server $DNSDB_SERVER",
				cf);
		f = popen(cmd, "r");
		if (f == NULL) {
			perror(cmd);
			exit(1);
		}
		if (debug)
			fprintf(stderr, "conf cmd = '%s'\n", cmd);
		free(cmd);
		while (fgets(line, sizeof line, f) != NULL) {
			if (strchr(line, '\n') == NULL) {
				fprintf(stderr, "%s: line too long\n", cf);
				exit(1);
			}
			if (debug)
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
				exit(1);
			}
		}
		pclose(f);
	}
}

static void
dnsdb_query(const char *command, int limit, present pres,
	    time_t after, time_t before)
{
	CURL *curl;

	if (debug)
		fprintf(stderr, "dnsdb_query(%s)\n", command);
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl != NULL) {
		struct curl_slist *headers = NULL;
		CURLcode res;
		char *url = NULL, *key_header = NULL;
		char sep = '?';
		int x;

		x = asprintf(&url, "%s/lookup/%s", dnsdb_server, command);
		if (x < 0) {
			perror("asprintf");
			exit(1);
		}
		if (limit != 0) {
			char *tmp;

			x = asprintf(&tmp, "%s%c" "limit=%d", url, sep, limit);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			free(url);
			url = tmp;
			tmp = NULL;
			sep = '&';
		}
		if (after != 0 && before != 0) {
			char *tmp;

			x = asprintf(&tmp, "%s%c"
				     "time_first_after=%lu"
				     "&time_last_before=%lu",
				     url, sep, (u_long)after, (u_long)before);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			free(url);
			url = tmp;
			tmp = NULL;
			sep = '&';
		} else if (after != 0) {
			char *tmp;

			x = asprintf(&tmp, "%s%c" "time_last_after=%lu",
				     url, sep, (u_long)after);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			free(url);
			url = tmp;
			tmp = NULL;
			sep = '&';
		} else if (before != 0) {
			char *tmp;

			x = asprintf(&tmp, "%s%c" "time_first_before=%lu",
				     url, sep, (u_long)before);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			free(url);
			url = tmp;
			tmp = NULL;
			sep = '&';
		}
		if (verbose)
			fprintf(filter ? stderr : stdout, "url [%s]\n", url);
		x = asprintf(&key_header, "X-Api-Key: %s", api_key);
		if (x < 0) {
			perror("asprintf");
			exit(1);
		}

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		headers = curl_slist_append(headers, key_header);
		headers = curl_slist_append(headers,
					    "Accept: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		/* libcurl default is to send json to stdout, so if that's
		 * what we're doing, and we're not sorting, don't override.
		 */
		if (pres != NULL || sorted != sort_not) {
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					 dnsdb_writer);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, pres);
			dnsdb_writer_init();
		}
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
 		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
		free(url);
		free(key_header);
		if (pres != NULL || sorted != sort_not)
			dnsdb_writer_fini(pres);
	}
 
	curl_global_cleanup();
}

static char *writer_buf = NULL;
static size_t writer_len = 0;
static FILE *sort_stdin, *sort_stdout;
static pid_t sort_pid;

static void
dnsdb_writer_init(void) {
	if (sorted != sort_not) {
		int p1[2], p2[2];

		if (pipe(p1) < 0 || pipe(p2) < 0) {
			perror("pipe");
			exit(1);
		}
		if ((sort_pid = fork()) < 0) {
			perror("fork");
			exit(1);
		}
		if (sort_pid == 0) {
			extern char **environ;
			char *sort_argv[6], **sap;

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
			*sap++ = (char *)"sort";
			*sap++ = (char *)"-k1";
			*sap++ = (char *)"-k2";
			*sap++ = (char *)"-n";
			if (sorted == sort_reverse)
				*sap++ = (char *)"-r";
			*sap++ = NULL;
			execve("/usr/bin/sort", sort_argv, environ);
			perror("execve");
			_exit(1);
		}
		close(p1[0]);
		sort_stdin = fdopen(p1[1], "w");
		sort_stdout = fdopen(p2[0], "r");
		close(p2[1]);
	}
}

static size_t
dnsdb_writer(char *ptr, size_t size, size_t nmemb, void *blob) {
	size_t bytes = size * nmemb;
	present pres = (present) blob;
	char *nl;

	if (debug)
		fprintf(stderr, "dnsdb_writer(%d, %d): %d\n",
			(int)size, (int)nmemb, (int)bytes);

	writer_buf = realloc(writer_buf, writer_len + bytes);
	memcpy(writer_buf + writer_len, ptr, bytes);
	writer_len += bytes;

	while ((nl = memchr(writer_buf, '\n', writer_len)) != NULL) {
		size_t pre_len, post_len;
		struct dnsdb_crack rec;
		const char *msg;

		if (dnsdb_writer_error())
			return (0);
		pre_len = nl - writer_buf;

		msg = dnsdb_crack_new(&rec, writer_buf, pre_len);
		if (msg) {
			puts(msg);
		} else {
			time_t first, last;

			if (rec.time_first != 0 && rec.time_last != 0) {
				first = rec.time_first;
				last = rec.time_last;
			} else {
				first = rec.zone_first;
				last = rec.zone_last;
			}
			if (sorted != sort_not) {
				fprintf(sort_stdin, "%lu %lu %*.*s\n",
					(unsigned long)first,
					(unsigned long)last,
					(int)pre_len, (int)pre_len,
					writer_buf);
				if (debug)
					fprintf(stderr,
						"sort_stdin: %lu %lu %*.*s\n",
						(unsigned long)first,
						(unsigned long)last,
						(int)pre_len, (int)pre_len,
						writer_buf);
			} else {
				(*pres)(&rec, stdout);
				dnsdb_crack_destroy(&rec);
			}
		}
		post_len = (writer_len - pre_len) - 1;
		memmove(writer_buf, nl + 1, post_len);
		writer_len = post_len;
	}
	return (bytes);
}

static void
dnsdb_writer_fini(present pres) {
	if (writer_buf != NULL) {
		(void) dnsdb_writer_error();
		free(writer_buf);
		writer_buf = NULL;
		if (writer_len != 0)
			fprintf(stderr, "stranding %d octets!\n",
				(int)writer_len);
		writer_len = 0;
	}
	if (sorted != sort_not) {
		char line[65536];
		int status;

		fclose(sort_stdin);
		while (fgets(line, sizeof line, sort_stdout) != NULL) {
			struct dnsdb_crack rec;
			char *nl, *linep;
			const char *msg;

			if ((nl = strchr(line, '\n')) == NULL) {
				fprintf(stderr, "no \\n found in '%s'\n",
					line);
				continue;
			}
			linep = line;
			/* skip time_first and time_last -- the sort keys. */
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr, "no SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr, "no SP found in '%s'\n", line);
				continue;
			}
			linep += strspn(linep, " ");
			if (pres == NULL) {
				fputs(linep, stdout);
				continue;
			}
			msg = dnsdb_crack_new(&rec, linep, nl - linep);
			if (msg != NULL) {
				puts(msg);
				continue;
			}
			(*pres)(&rec, stdout);
			dnsdb_crack_destroy(&rec);
		}
		fclose(sort_stdout);
		if (waitpid(sort_pid, &status, 0) < 0) {
			perror("waitpid");
		} else {
			if (status != 0)
				fprintf(stderr, "sort exit status is %u\n",
					status);
		}
	}
}

static int
dnsdb_writer_error(void) {
	if (writer_buf[0] != '\0' && writer_buf[0] != '{') {
		fprintf(stderr, "API: %-*.*s",
		       (int)writer_len, (int)writer_len, writer_buf);
		writer_buf[0] = '\0';
		writer_len = 0;
		return (1);
	}
	return (0);
}

static void
present_dns(const struct dnsdb_crack *rec, FILE *outf) {
	int pflag, ppflag;
	const char *prefix;

	ppflag = 0;

	/* Timestamps. */
	if (rec->obj.time_first != NULL && rec->obj.time_last != NULL) {
		fputs(";; record times: ", outf);
		time_print(rec->time_first, FALSE, outf);
		fputs(" .. ", outf);
		time_print(rec->time_last, FALSE, outf);
		putc('\n', outf);
		ppflag++;
	}
	if (rec->obj.zone_first != NULL && rec->obj.zone_last != NULL) {
		fputs(";;   zone times: ", outf);
		time_print(rec->zone_first, FALSE, outf);
		fputs(" .. ", outf);
		time_print(rec->zone_last, FALSE, outf);
		putc('\n', outf);
		ppflag++;
	}

	/* Count and Bailiwick. */
	prefix = ";;";
	pflag = 0;
	if (rec->obj.count != NULL) {
		fprintf(outf, "%s count: %lld", prefix, (long long)rec->count);
		prefix = ";";
		pflag++;
		ppflag++;
	}
	if (rec->obj.bailiwick != NULL) {
		fprintf(outf, "%s bailiwick: %s", prefix, rec->bailiwick);
		prefix = ";";
		pflag++;
		ppflag++;
	}
	if (pflag)
		putc('\n', outf);

	/* Records. */
	if (json_is_array(rec->obj.rdata)) {
		size_t slot, nslots;

		nslots = json_array_size(rec->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(rec->obj.rdata, slot);
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			fprintf(outf, "%s  %s  %s\n",
				rec->rrname, rec->rrtype, rdata);
			ppflag++;
		}
	} else {
		fprintf(outf, "%s  %s  %s\n",
			rec->rrname, rec->rrtype, rec->rdata);
		ppflag++;
	}

	/* Cleanup. */
	if (ppflag)
		putc('\n', outf);
}

static int dnsdb_out_csv_headerp = 0;

static void
present_csv(const struct dnsdb_crack *rec, FILE *outf) {
	if (!dnsdb_out_csv_headerp) {
		fprintf(outf,
			"time_first,time_last,zone_first,zone_last,"
			"count,bailiwick,"
			"rrname,rrtype,rdata\n");
		dnsdb_out_csv_headerp = 1;
	}

	if (json_is_array(rec->obj.rdata)) {
		size_t slot, nslots;

		nslots = json_array_size(rec->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(rec->obj.rdata, slot);
			const char *rdata = NULL;

			if (json_is_string(rr))
				rdata = json_string_value(rr);
			else
				rdata = "[bad value]";
			present_csv_line(rec, rdata, outf);
		}
	} else {
		present_csv_line(rec, rec->rdata, outf);
	}
}

static void
present_csv_line(const struct dnsdb_crack *rec,
		 const char *rdata,
		 FILE *outf)
{
	/* Timestamps. */
	if (rec->obj.time_first != NULL)
		time_print(rec->time_first, TRUE, outf);
	putc(',', outf);
	if (rec->obj.time_last != NULL)
		time_print(rec->time_last, TRUE, outf);
	putc(',', outf);
	if (rec->obj.zone_first != NULL)
		time_print(rec->zone_first, TRUE, outf);
	putc(',', outf);
	if (rec->obj.zone_last != NULL)
		time_print(rec->zone_last, TRUE, outf);
	putc(',', outf);

	/* Count and bailiwick. */
	if (rec->obj.count != NULL)
		fprintf(outf, "%lld", (long long) rec->count);
	putc(',', outf);
	if (rec->obj.bailiwick != NULL)
		fprintf(outf, "\"%s\"", rec->bailiwick);
	putc(',', outf);

	/* Records. */
	if (rec->obj.rrname != NULL)
		fprintf(outf, "\"%s\"", rec->rrname);
	putc(',', outf);
	if (rec->obj.rrtype != NULL)
		fprintf(outf, "\"%s\"", rec->rrtype);
	putc(',', outf);
	if (rec->obj.rdata != NULL)
		fprintf(outf, "\"%s\"", rdata);
	putc('\n', outf);
}

static const char *
dnsdb_crack_new(struct dnsdb_crack *rec, char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

	memset(rec, 0, sizeof *rec);
	if (debug)
		fprintf(stderr, "[%d] '%-*.*s'\n",
			(int)len, (int)len, (int)len, buf);
	rec->obj.main = json_loadb(buf, len, 0, &error);
	if (rec->obj.main == NULL) {
		fprintf(stderr, "%d:%d: %s %s\n",
		       error.line, error.column,
		       error.text, error.source);
		abort();
	}
	if (debug) {
		fputs("---\n", stderr);
		json_dumpf(rec->obj.main, stderr, JSON_INDENT(2));
		fputs("\n===\n", stderr);
	}

	/* Timestamps. */
	rec->obj.zone_first = json_object_get(rec->obj.main,
					      "zone_time_first");
	if (rec->obj.zone_first != NULL) {
		if (!json_is_integer(rec->obj.zone_first)) {
			msg = "zone_time_first must be an integer";
			goto ouch;
		}
		rec->zone_first = (time_t)
			json_integer_value(rec->obj.zone_first);
	}
	rec->obj.zone_last = json_object_get(rec->obj.main, "zone_time_last");
	if (rec->obj.zone_last != NULL) {
		if (!json_is_integer(rec->obj.zone_last)) {
			msg = "zone_time_last must be an integer";
			goto ouch;
		}
		rec->zone_last = (time_t)
			json_integer_value(rec->obj.zone_last);
	}
	rec->obj.time_first = json_object_get(rec->obj.main, "time_first");
	if (rec->obj.time_first != NULL) {
		if (!json_is_integer(rec->obj.time_first)) {
			msg = "time_first must be an integer";
			goto ouch;
		}
		rec->time_first = (time_t)
			json_integer_value(rec->obj.time_first);
	}
	rec->obj.time_last = json_object_get(rec->obj.main, "time_last");
	if (rec->obj.time_last != NULL) {
		if (!json_is_integer(rec->obj.time_last)) {
			msg = "time_last must be an integer";
			goto ouch;
		}
		rec->time_last = (time_t)
			json_integer_value(rec->obj.time_last);
	}

	/* Count and Bailiwick. */
	rec->obj.count = json_object_get(rec->obj.main, "count");
	if (rec->obj.count != NULL) {
		if (!json_is_integer(rec->obj.count)) {
			msg = "count must be an integer";
			goto ouch;
		}
		rec->count = json_integer_value(rec->obj.count);
	}
	rec->obj.bailiwick = json_object_get(rec->obj.main, "bailiwick");
	if (rec->obj.bailiwick != NULL) {
		if (!json_is_string(rec->obj.bailiwick)) {
			msg = "bailiwick must be a string";
			goto ouch;
		}
		rec->bailiwick = json_string_value(rec->obj.bailiwick);
	}

	/* Records. */
	rec->obj.rrname = json_object_get(rec->obj.main, "rrname");
	if (rec->obj.rrname != NULL) {
		if (!json_is_string(rec->obj.rrname)) {
			msg = "rrname must be a string";
			goto ouch;
		}
		rec->rrname = json_string_value(rec->obj.rrname);
	}
	rec->obj.rrtype = json_object_get(rec->obj.main, "rrtype");
	if (rec->obj.rrtype != NULL) {
		if (!json_is_string(rec->obj.rrtype)) {
			msg = "rrtype must be a string";
			goto ouch;
		}
		rec->rrtype = json_string_value(rec->obj.rrtype);
	}
	rec->obj.rdata = json_object_get(rec->obj.main, "rdata");
	if (rec->obj.rdata != NULL) {
		if (json_is_string(rec->obj.rdata)) {
			rec->rdata = json_string_value(rec->obj.rdata);
		} else if (!json_is_array(rec->obj.rdata)) {
			msg = "rdata must be a string or array";
			goto ouch;
		}
		/* N.b., the array case is for the consumer to iterate over. */
	}

	assert(msg == NULL);
	return (NULL);

 ouch:
	assert(msg != NULL);
	dnsdb_crack_destroy(rec);
	return (msg);
}

static void
dnsdb_crack_destroy(struct dnsdb_crack *rec) {
	json_decref(rec->obj.main);
	if (debug)
		memset(rec, 0x5a, sizeof *rec);
}

static void
time_print(time_t x, int rfc3339, FILE *outf) {
	struct tm *y = gmtime(&x);
	char z[99];

	strftime(z, sizeof z, rfc3339 ? "%FT%TZ" : "%F %T", y);
	fputs(z, outf);
}

static int
time_get(const char *src, time_t *dst) {
	char *endptr;
	struct tm tt;
	u_long t;

	if (strptime(src, "%Y-%m-%d %H:%M:%S", &tt) != NULL ||
	    strptime(src, "%Y-%m-%d", &tt) != NULL)
	{
		*dst = (u_long) mktime(&tt);
		return (1);
	}
	t = strtoul(src, &endptr, 10);
	if (*src != '\0' && *endptr == '\0') {
		*dst = (time_t) t;
		return (1);
	}
	if (ns_parse_ttl(src, &t) == 0) {
		*dst = (time_t) (((u_long) time(NULL)) - t);
		return (1);
	}
	return (0);
}
