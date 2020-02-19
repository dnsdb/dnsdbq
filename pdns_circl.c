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

#if WANT_PDNS_CIRCL

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <stdio.h>

#include "defs.h"
#include "pdns.h"
#include "pdns_circl.h"
#include "globals.h"

static char *circl_url(const char *, char *);
static void circl_auth(fetch_t);
static const char *circl_status(fetch_t);
static const char *circl_verb_ok(const char *);
static void circl_ready(void);
static const char *circl_setenv(const char *, const char *);
static void circl_destroy(void);

static char *circl_base_url = NULL;
static char *circl_authinfo = NULL;

static const struct pdns_system circl = {
	"circl", "https://www.circl.lu/pdns/query",
	circl_url, NULL, NULL,
	circl_auth, circl_status, circl_verb_ok,
	circl_setenv, circl_ready, circl_destroy
};

pdns_system_ct
pdns_circl(void) {
	return &circl;
}

static const char *
circl_setenv(const char *key, const char *value) {
	if (strcmp(key, "apikey") == 0) {
		DESTROY(circl_authinfo);
		circl_authinfo = strdup(value);
	} else if (strcmp(key, "server") == 0) {
		DESTROY(circl_base_url);
		circl_base_url = strdup(value);
	} else {
		return "circl_setenv() unrecognized key";
	}
	return NULL;
}

static void
circl_ready(void) {
}

static void
circl_destroy(void) {
	DESTROY(circl_base_url);
	DESTROY(circl_authinfo);
}

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
		circl_base_url = strdup(psys->base_url);

	for (pi = 0; valid_paths[pi] != NULL; pi++)
		if (strncasecmp(path, valid_paths[pi], strlen(valid_paths[pi]))
		    == 0)
		{
			val = path + strlen(valid_paths[pi]);
			break;
		}
	if (val == NULL) {
		fprintf(stderr,
			"%s: unsupported type of query for CIRCL pDNS: %s\n",
			program_name, path);
		my_exit(1);
	}

	if (strchr(val, '/') != NULL) {
		fprintf(stderr,
			"%s: qualifiers not supported by CIRCL pDNS: %s\n",
			program_name, val);
		my_exit(1);
	}
	x = asprintf(&ret, "%s/%s", circl_base_url, val);
	if (x < 0)
		my_panic(true, "asprintf");

	/* because we will NOT append query parameters,
	 * tell the caller to use ? for its query parameters.
	 */
	if (sep != NULL)
		*sep = '?';

	return (ret);
}

static void
circl_auth(fetch_t fetch) {
	if (fetch->easy != NULL) {
		curl_easy_setopt(fetch->easy, CURLOPT_USERPWD,
				 circl_authinfo);
		curl_easy_setopt(fetch->easy, CURLOPT_HTTPAUTH,
				 CURLAUTH_BASIC);
	}
}

static const char *
circl_status(fetch_t fetch __attribute__((unused))) {
	return "ERROR";
}

static const char *
circl_verb_ok(const char *verb_name) {
	/* Only "lookup" is valid */
	if (strcasecmp(verb_name, "lookup") != 0)
		return ("the CIRCL system only understands 'lookup'");
	return (NULL);
}

#endif /*WANT_PDNS_CIRCL*/
