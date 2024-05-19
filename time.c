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

#define _GNU_SOURCE
#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "defs.h"
#include "time.h"
#include "globals.h"
#include "ns_ttl.h"

/* time_cmp -- compare two absolute timestamps, give -1, 0, or 1.
 */
int
time_cmp(u_long a, u_long b) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

/* time_str -- format one (possibly zero) timestamp
 *
 *	returns static string. always uses GMT.
 */
const char *
time_str(u_long x, bool iso8601fmt) {
	static char ret[sizeof "yyyy-mm-ddThh:mm:ssZ"];

	if (x == 0) {
		strcpy(ret, "0");
	} else {
		time_t t = (time_t)x;
		struct tm result, *y = gmtime_r(&t, &result);

		strftime(ret, sizeof ret, iso8601fmt ? "%FT%TZ" : "%F %T", y);
	}
	return ret;
}

/* timeval_str -- format one timeval (NULL means current time)
 *
 * returns static string. always uses GMT.
 *
 * output format: yyyy-mm-dd hh:mm:ss.fff[fff]
 */
const char *
timeval_str(const struct timeval *src, bool milliseconds) {
	static char ret[sizeof "yyyy-mm-dd hh:mm:ss.ffffff"];
	char *dst;

	struct timeval now;
	if (src == NULL) {
		gettimeofday(&now, NULL);
		src = &now;
	}

	time_t t = (time_t)src->tv_sec;
	struct tm result, *y = gmtime_r(&t, &result);
	dst = ret + strftime(ret, sizeof ret, "%F %T", y);
	long usecs = (long)src->tv_usec;
	if (milliseconds)
		sprintf(dst, ".%03ld", usecs % 1000);
	else
		sprintf(dst, ".%06ld", usecs % 1000000);
	return ret;
}

/* time_get -- parse and return one (possibly relative) timestamp.
 */
int
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
		return 1;
	}
	ll = strtoll(src, &ep, 10);
	if (*src != '\0' && *ep == '\0') {
		if (ll < 0)
			*dst = (u_long)startup_time.tv_sec -
				(u_long)imaxabs(ll);
		else
			*dst = (u_long)ll;
		return 1;
	}
	if (ns_parse_ttl(src, &t) == 0) {
		*dst = (u_long)startup_time.tv_sec - t;
		return 1;
	}
	return 0;
}

