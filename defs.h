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

#ifndef DEFS_H_INCLUDED
#define DEFS_H_INCLUDED 1

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Note that cygwin has a crippled libresolv that does not
 * include the not so recent ns_initparse() function, etc.
 * This AS info functionality is thus not available
 * in cygwin.
 */
#ifdef __CYGWIN__
#define CRIPPLED_LIBC 1
#endif /* __CYGWIN__ */

#define DEFAULT_SYS "dnsdb2"
#define DEFAULT_VERB 0
#define	MAX_JOBS 8
#define DNSDBQ_SYSTEM "DNSDBQ_SYSTEM"

#define CREATE(p, s) if ((p) != NULL) { my_panic(false, "non-NULL ptr"); } \
	else if (((p) = malloc(s)) == NULL) { my_panic(true, "malloc"); } \
	else { memset((p), 0, s); }
#define DESTROY(p) { if ((p) != NULL) { free(p); (p) = NULL; } }
#define DEBUG(ge, ...) { if (debug_level >= (ge)) debug(__VA_ARGS__); }

typedef enum { pres_text, pres_json, pres_csv } present_e;
typedef enum { batch_none, batch_terse, batch_verbose } batch_e;

/* or_else -- return one pointer or else the other.
 */
static inline const char *
or_else(const char *p, const char *or_else) {
	if (p != NULL)
		return p;
	return or_else;
}

/* debug -- at the moment, dump to stderr.
 */
static inline void
debug(bool want_header, const char *fmtstr, ...) {
	va_list ap;

	va_start(ap, fmtstr);
	if (want_header)
		fputs("debug: ", stderr);
	vfprintf(stderr, fmtstr, ap);
	va_end(ap);
}

#endif /*DEFS_H_INCLUDED*/
