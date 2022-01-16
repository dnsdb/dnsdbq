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

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "defs.h"
#include "sort.h"
#include "globals.h"

/* in the POSIX sort(1) intermediate format, the fields are:
 * #1 first
 * #2 last
 * #3 duration
 * #4 count
 * #5 rrname
 * #7 rrtype
 * #6 rdata
 * #8 mode
 * #9 json
 */

#define	MAX_KEYS 7

extern char **environ;

static struct sortkey keys[MAX_KEYS];
static int nkeys = 0;

/* sort_ready -- finish initializing the sort related metadata.
 *
 * If sorting, all keys must be specified, to enable -u.
 * This adds every possible sort key, ignoring any errors from adding
 * a key in case the key was already added as specified by the user.
 */
void
sort_ready(void) {
	(void) add_sort_key("first");
	(void) add_sort_key("last");
	(void) add_sort_key("duration");
	(void) add_sort_key("count");
	(void) add_sort_key("name");
	(void) add_sort_key("type");
	(void) add_sort_key("data");
}

/* add_sort_key -- add a key for use by POSIX sort.
 *
 * Returns NULL if no error, otherwise a static error message.
 */
const char *
add_sort_key(const char *key_name) {
	const char *key = NULL;
	char *computed;
	int x;

	if (nkeys == MAX_KEYS)
		return "too many sort keys given.";
	if (strcasecmp(key_name, "first") == 0)
		key = "-k1n";
	else if (strcasecmp(key_name, "last") == 0)
		key = "-k2n";
	else if (strcasecmp(key_name, "duration") == 0)
		key = "-k3n";
	else if (strcasecmp(key_name, "count") == 0)
		key = "-k4n";
	else if (strcasecmp(key_name, "name") == 0)
		key = "-k5";
	else if (strcasecmp(key_name, "type") == 0)
		key = "-k6";
	else if (strcasecmp(key_name, "data") == 0)
		key = "-k7";
	else
		return "key must be in "
		        "first|last|duration|count|name|type|data";
	x = asprintf(&computed, "%s%s", key,
		     sorting == reverse_sort ? "r" : "");
	if (x < 0)
		my_panic(true, "asprintf");
	keys[nkeys++] = (struct sortkey){strdup(key_name), computed};
	return NULL;
}

/* find_sort_key -- return pointer to a sort key, or NULL if it's not specified
 */
sortkey_ct
find_sort_key(const char *key_name) {
	int n;

	for (n = 0; n < nkeys; n++) {
		if (strcmp(keys[n].specified, key_name) == 0)
			return &keys[n];
	}
	return NULL;
}

/* sort_destroy -- drop sort metadata from heap.
 */
void
sort_destroy(void) {
	int n;

	for (n = 0; n < nkeys; n++) {
		DESTROY(keys[n].specified);
		DESTROY(keys[n].computed);
	}
}

/* exec_sort -- replace this fork with a POSIX sort program
 */
__attribute__((noreturn)) void
exec_sort(int p1[], int p2[]) {
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
	for (n = 0; n < nkeys; n++)
		*sap++ = strdup(keys[n].computed);
	*sap++ = NULL;
	putenv(strdup("LC_ALL=C"));
	DEBUG(1, true, "\"%s\" args:", path_sort);
	for (sap = sort_argv; *sap != NULL; sap++)
		DEBUG(1, false, " [%s]", *sap);
	DEBUG(1, false, "\n");
	execve(path_sort, sort_argv, environ);
	perror("execve");
	for (sap = sort_argv; *sap != NULL; sap++)
		DESTROY(*sap);
	_exit(1);
}

/* sortable_rrname -- return a POSIX-sort-collatable rendition of RR name+type.
 */
char *
sortable_rrname(pdns_tuple_ct tup) {
	struct sortbuf buf = {};

	sortable_dnsname(&buf, json_string_value(tup->obj.rrname));
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return buf.base;
}

/* sortable_rdata -- return a POSIX-sort-collatable rendition of RR data set.
 */
char *
sortable_rdata(pdns_tuple_ct tup) {
	struct sortbuf buf = {};

	if (json_is_array(tup->obj.rdata)) {
		size_t index;
		json_t *rr;

		json_array_foreach(tup->obj.rdata, index, rr) {
			if (json_is_string(rr))
				sortable_rdatum(&buf, tup->rrtype,
						json_string_value(rr));
			else
				fprintf(stderr,
					"%s: warning: rdata slot "
					"is not a string\n",
					program_name);
		}
	} else {
		sortable_rdatum(&buf, tup->rrtype, tup->rdata);
	}
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return buf.base;
}

/* sortable_rdatum -- called only by sortable_rdata(), realloc and normalize.
 *
 * this converts (lossily) addresses into hex strings, and extracts the
 * server-name component of a few other types like MX. all other rdata
 * are left in their normal string form, because it's hard to know what
 * to sort by with something like TXT, and extracting the serial number
 * from an SOA using a language like C is a bit ugly.
 */
void
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
		   strcmp(rrtype, "CNAME") == 0 ||
		   strcmp(rrtype, "DNAME") == 0)
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

/* sortable_hexify -- convert src into hex string in buffer
 */
void
sortable_hexify(sortbuf_t buf, const u_char *src, size_t len) {
	buf->base = realloc(buf->base, buf->size + len*2);
	for (size_t i = 0; i < len; i++) {
		static const char hex[] = "0123456789abcdef";
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
void
sortable_dnsname(sortbuf_t buf, const char *name) {
	struct counted *c = countoff(name);

	// ensure our result buffer is large enough.
	size_t new_size = buf->size + c->nalnum;
	if (new_size == 0) {
		DESTROY(c);
		buf->base = realloc(buf->base, 1);
		buf->base[0] = '.';
		buf->size = 1;
		return;
	}
	if (new_size != buf->size)
		buf->base = realloc(buf->base, new_size);
	char *p = buf->base + buf->size;

	// collatable names are TLD-first, alphanumeric only, lower case.
	size_t nchar = 0;
	for (ssize_t i = (ssize_t)(c->nlabel-1); i >= 0; i--) {
		size_t dot = (name[c->nchar - nchar - 1] == '.');
		ssize_t j = (ssize_t)(c->lens[i] - dot);
		ssize_t k = (ssize_t)(c->nchar - nchar - c->lens[i]);
		for (ssize_t l = k; l < j+k; l++) {
			int ch = name[l];
			if (isalnum(ch))
				*p++ = (char) tolower(ch);
		}
		nchar += c->lens[i];
	}
	DESTROY(c);

	// update our counted-string output.
	buf->size = (size_t)(p - buf->base);
	assert(buf->size == new_size);
}
