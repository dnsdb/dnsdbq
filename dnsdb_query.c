/* Copyright (C) 2014, Farsight Security, Inc. No rights reserved. */

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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <curl/curl.h>
#include <jansson.h>

/* Internal. */

#define DNSDB_SERVER "https://api.dnsdb.info"
#define DNSDB_CONF "dnsdb-query.conf"

struct dnsdb_config_opts
{
    char api_key[256];
    char server[256];
    int fmt;
#define FORMAT_JSON 1
#define FORMAT_TEXT 2
#define FORMAT_CSV  3
};

struct dnsdb_crack {
	struct {
		json_t *main, *time_first, *time_last, *zone_first, *zone_last,
			*count, *bailiwick, *rrname, *rrtype, *rdata;
	} obj;
	time_t time_first, time_last, zone_first, zone_last;
	const char *bailiwick, *rrname, *rrtype, *rdata;
	int count;
};

typedef void (*present)(const struct dnsdb_crack *, FILE *);

static int verbose = 0;
static int debug = 0;

/* Forward. */

static void usage(void)  __attribute__((__noreturn__));
static void dnsdb_query(const char *command, const char *api_key,
			const char *dnsdb_server, int limit, present);
static void present_dns(const struct dnsdb_crack *, FILE *);
static void present_csv(const struct dnsdb_crack *, FILE *);
static void present_csv_line(const struct dnsdb_crack *, const char *, FILE *);
static const char *dnsdb_crack_new(struct dnsdb_crack *, char *, size_t);
static void dnsdb_crack_destroy(struct dnsdb_crack *);
static size_t dnsdb_writer(char *ptr, size_t size, size_t nmemb, void *blob);
static void dnsdb_writer_fini(void);
static int dnsdb_writer_error(void);

static void time_print(time_t x, FILE *);
FILE *conf_open(char *);
int conf_parse(FILE *, struct dnsdb_config_opts *);

/* Public. */

int
main(int argc, char *argv[]) {
	char *command = NULL;
    /* 
     * Options are parsed from environment but will be overwritten if a config
     * file is found / specified and contains the same options.
     *
     * Special case: -t or -j at command line will override envrionment and
     * config file.
     */
	const char *api_key = getenv("DNSDB_API_KEY");
	const char *dnsdb_server = getenv("DNSDB_SERVER");
    const char *dnsdb_format = getenv("DNSDB_FORMAT");
    const char *home = getenv("HOME");
    char *config_file = NULL;
    char config_prefix[PATH_MAX];
    FILE *fp;
	int ch, limit = 0, format_set = 0;
	present pres = present_dns;
    struct dnsdb_config_opts config_opts;

	while ((ch = getopt(argc, argv, "c:r:n:i:l:t:hvdj")) != -1) {
		int x;

		switch (ch) {
        case 'c':
            config_file = optarg;
            break;
		case 'r':
			if (command != NULL)
				usage();
			x = asprintf(&command, "rrset/name/%s", optarg);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			break;
		case 'n':
			if (command != NULL)
				usage();
			x = asprintf(&command, "rdata/name/%s", optarg);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			break;
		case 'i': {
			const char *p;

			if (command != NULL)
				usage();
			if ((p = strchr(optarg, '/')) != NULL)
				x = asprintf(&command, "rdata/ip/%-*.*s,%s",
					     (int) (p - optarg),
					     (int) (p - optarg),
					     optarg, p + 1);
			else
				x = asprintf(&command, "rdata/ip/%s", optarg);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			break;
		    }
		case 't':
            format_set = 1;
			if (strcmp(optarg, "json") == 0)
				pres = NULL;
			else if (strcmp(optarg, "dns") == 0)
				pres = present_dns;
			else if (strcmp(optarg, "csv") == 0)
				pres = present_csv;
			else
				usage();
			break;
		case 'l':
			limit = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			debug++;
			break;
		case 'j':
            format_set = 1;
			pres = NULL;
			break;
		case 'h':
			/*FALLTHROUGH*/
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (command == NULL)
		usage();

    /* if user didn't specify -t or -j AND there's a format env var, parse it */
    if (format_set == 0 && dnsdb_format)
    {
        if (strncmp(dnsdb_format, "text", 4) == 0)
        {
            pres = present_dns;
        }
        else if (strncmp(dnsdb_format, "json", 4) == 0)
        {
            pres = NULL;
        }
        else if (strncmp(dnsdb_format, "csv", 4) == 0)
        {
            pres = present_csv;
        }
        else
        {
            fprintf(stderr, "igorning unknown DNSDB_FORMAT env var: %s\n", 
                    dnsdb_format);
        }
    }
    /* try to open user-specified config, hard fail if something goes wrong */
    if (config_file)
    {
        fp = fopen(config_file, "r");
        if (fp == NULL)
        {
            fprintf(stderr, "can't open %s: %s\n", config_file, 
                    strerror(errno));
            return (0);
        }
    }
    else
    {
        /* first try to open systemwide default conf */
        strncpy(config_prefix, "/etc/", 5);
        fp = conf_open(config_prefix);
        if (fp == NULL)
        {
            /* if that doesn't work, try to open (dot)conf in user's $HOME */
            strncpy(config_prefix, home, PATH_MAX);
            strncpy(config_prefix + strlen(home), "/.", PATH_MAX - 2 - 
                    strlen(home));
            fp = conf_open(config_prefix);
        }
    }
    if (fp)
    {
        /* examine conf file for options and set 'em if we find 'em */
        if (conf_parse(fp, &config_opts) == -1)
        {
            fprintf(stderr, "config file contains invalid options\n");
            exit(1);
        }
        else
        {
            api_key = config_opts.api_key;
            dnsdb_server = config_opts.server;
            /* user didn't specify -t or -j, let's use what's in the config */
            if (format_set == 0)
            {
                switch (config_opts.fmt)
                {
                    case FORMAT_JSON:
                        pres = NULL;
                        break;
                    case FORMAT_TEXT:
                        pres = present_dns;
                        break;
                    case FORMAT_CSV:
                        pres = present_csv;
                        break;
                }
            }
        }
    }
	if (api_key == NULL) {
		fprintf(stderr, "must set DNSDB_API_KEY in environment\n");
		exit(1);
	}
	if (dnsdb_server == NULL)
		dnsdb_server = DNSDB_SERVER;
	dnsdb_query(command, api_key, dnsdb_server, limit, pres);
	free(command);
	return (0);
}

/* Private. */

static void usage(void) {
	fprintf(stderr,
"usage: dnsdb_query [-v] [-d] [-h] [-j] [-t json|csv] [-l LIMIT] [-c config]\n"
"\t{-r OWNER[/TYPE[/BAILIWICK]]\n"
"\t\t| -n NAME[/TYPE]\n"
"\t\t| -i IP[/PFXLEN]\n"
"\t}\n"
		);
	exit(1);
}

static void
dnsdb_query(const char *command, const char *api_key,
	    const char *dnsdb_server, int limit,
	    present pres)
{
	CURL *curl;

	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();
	if (curl != NULL) {
		struct curl_slist *headers = NULL;
		CURLcode res;
		char *url = NULL, *key_header = NULL;
		int x;

		x = asprintf(&url, "%s/lookup/%s", dnsdb_server, command);
		if (x < 0) {
			perror("asprintf");
			exit(1);
		}
		if (limit != 0) {
			char *tmp;

			x = asprintf(&tmp, "%s?limit=%d", url, limit);
			if (x < 0) {
				perror("asprintf");
				exit(1);
			}
			free(url);
			url = tmp;
			tmp = NULL;
		}
		if (verbose)
			printf("url [%s]\n", url);
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
		if (pres != NULL) {
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					 dnsdb_writer);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, pres);
		}
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
 		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
		free(url);
		free(key_header);
		dnsdb_writer_fini();
	}
 
	curl_global_cleanup();
}

static char *writer_buf = NULL;
static size_t writer_len = 0;

static size_t
dnsdb_writer(char *ptr, size_t size, size_t nmemb, void *blob) {
	size_t bytes = size * nmemb;
	present pres = (present) blob;
	char *nl;

	if (debug)
		printf("dnsdb_writer(%d, %d): %d\n",
			(int)size, (int)nmemb, (int)bytes);

	writer_buf = realloc(writer_buf, writer_len + bytes);
	memcpy(writer_buf + writer_len, ptr, bytes);
	writer_len += bytes;

	while ((nl = memchr(writer_buf, '\n', writer_len)) != NULL) {
		struct dnsdb_crack rec;
		const char *msg;
		size_t pre_len, post_len;

		if (dnsdb_writer_error())
			return (0);
		pre_len = nl - writer_buf;
		msg = dnsdb_crack_new(&rec, writer_buf, pre_len);
		if (msg) {
			printf("%s\n", msg);
		} else {
			(*pres)(&rec, stdout);
			dnsdb_crack_destroy(&rec);
		}
		post_len = (writer_len - pre_len) - 1;
		memmove(writer_buf, nl + 1, post_len);
		writer_len = post_len;
	}
	return (bytes);
}

static void
dnsdb_writer_fini(void) {
	if (writer_buf != NULL) {
		(void) dnsdb_writer_error();
		free(writer_buf);
		writer_buf = NULL;
		if (writer_len != 0)
			fprintf(stderr, "stranding %d octets!\n",
				(int)writer_len);
		writer_len = 0;
	}
}

static int
dnsdb_writer_error(void) {
	if (writer_buf[0] != '\0' && writer_buf[0] != '{') {
		printf("API: %-*.*s",
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
		time_print(rec->time_first, outf);
		fputs(" .. ", outf);
		time_print(rec->time_last, outf);
		putc('\n', outf);
		ppflag++;
	}
	if (rec->obj.zone_first != NULL && rec->obj.zone_last != NULL) {
		fputs(";;   zone times: ", outf);
		time_print(rec->zone_first, outf);
		fputs(" .. ", outf);
		time_print(rec->zone_last, outf);
		putc('\n', outf);
		ppflag++;
	}

	/* Count and Bailiwick. */
	prefix = ";;";
	pflag = 0;
	if (rec->obj.count != NULL) {
		fprintf(outf, "%s count: %d", prefix, rec->count);
		prefix = ";";
		pflag++;;
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
			json_decref(rr);
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
			json_decref(rr);
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
		time_print(rec->time_first, outf);
	putc(',', outf);
	if (rec->obj.time_last != NULL)
		time_print(rec->time_last, outf);
	putc(',', outf);
	if (rec->obj.zone_first != NULL)
		time_print(rec->zone_first, outf);
	putc(',', outf);
	if (rec->obj.zone_last != NULL)
		time_print(rec->zone_last, outf);
	putc(',', outf);

	/* Count and bailiwick. */
	if (rec->obj.count != NULL)
		fprintf(outf, "%lu", (unsigned long) rec->count);
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
		printf("[%d] '%-*.*s'\n", (int)len, (int)len, (int)len, buf);
	rec->obj.main = json_loadb(buf, len, 0, &error);
	if (rec->obj.main == NULL) {
		printf("%d:%d: %s %s\n",
		       error.line, error.column,
		       error.text, error.source);
		abort();
	}
	if (debug) {
		fputs("---\n", stdout);
		json_dumpf(rec->obj.main, stdout, JSON_INDENT(2));
		fputs("\n===\n", stdout);
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
		rec->count = (int) json_integer_value(rec->obj.count);
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
	if (rec->obj.time_first)
		json_decref(rec->obj.time_first);
	if (rec->obj.time_last)
		json_decref(rec->obj.time_last);
	if (rec->obj.zone_first)
		json_decref(rec->obj.zone_first);
	if (rec->obj.zone_last)
		json_decref(rec->obj.zone_last);
	if (rec->obj.count)
		json_decref(rec->obj.count);
	if (rec->obj.bailiwick)
		json_decref(rec->obj.bailiwick);
	if (rec->obj.rrtype)
		json_decref(rec->obj.rrtype);
	if (rec->obj.rrname)
		json_decref(rec->obj.rrname);
	if (rec->obj.rdata)
		json_decref(rec->obj.rdata);
	json_decref(rec->obj.main);
}

static void
time_print(time_t x, FILE *outf) {
	struct tm *y = gmtime(&x);
	char z[99];

	strftime(z, sizeof z, "%F %T", y);
	fputs(z, outf);
}

FILE *
conf_open(char *prefix)
{   
    char file_name[PATH_MAX];
    int prefix_siz = strlen(prefix);
    FILE *fp;

    memset(file_name, 0, PATH_MAX);
    strncpy(file_name, prefix, PATH_MAX - 1);
    strncpy(file_name + prefix_siz, DNSDB_CONF, PATH_MAX - 1 - prefix_siz);

    fp = fopen(file_name, "r");
    if (fp == NULL)
    {   
       if (errno != ENOENT)
       {
           fprintf(stderr, "can't open %s: %s\n", file_name, strerror(errno));
       }
       return NULL;
    }   
    return fp;
}

int 
conf_parse(FILE *fp, struct dnsdb_config_opts *opts)
{
    char buf[BUFSIZ];
    char *p, *q;

    while (fgets(buf, BUFSIZ, fp))
    {
        if (buf[0] == '#' || isspace(buf[0]))
        {
            continue;
        }
        p = buf;
        if (strncmp(buf, "APIKEY", 6) == 0)
        {
            q = strsep(&p, "=");
            if (q == NULL || p == NULL)
            {
                fprintf(stderr, "invalid APIKEY config option: %s\n", buf);
                return -1;
            }
            strncpy(opts->api_key, p, 255);
            opts->api_key[strlen(opts->api_key) - 1] = 0;
            continue;
        }
        else if (strncmp(buf, "DNSDB_SERVER", 12) == 0)
        {
            q = strsep(&p, "=");
            if (q == NULL || p == NULL)
            {
                fprintf(stderr, "invalid DNSDB_SERVER config option: %s\n",
                        buf);
                return -1;
            }
            strncpy(opts->server, p, 255);
            opts->server[strlen(opts->server) - 1] = 0;
            continue;
        }
        else if (strncmp(buf, "DNSDB_FORMAT", 12) == 0)
        {
            q = strsep(&p, "=");
            if (q == NULL || p == NULL)
            {
                fprintf(stderr, "invalid DNSDB_FORMAT config option: %s\n",
                        buf);
                return -1;
            }
            if (strncmp(p, "json", 4) == 0)
            {
                opts->fmt = FORMAT_JSON;
            }
            else if (strncmp(p, "text", 4) == 0)
            {
                opts->fmt = FORMAT_TEXT;
            }
            else if (strncmp(p, "csv", 3) == 0)
            {
                opts->fmt = FORMAT_CSV;
            }
            else
            {
                fprintf(stderr, "invalid DNSDB_FORMAT config option: %s\n", p);
                return -1;
            }
            continue;
        }
        else
        {
            fprintf(stderr, "unrecognized option: %s\n", buf);
            return -1;
        }
    }
    return 1;
}

