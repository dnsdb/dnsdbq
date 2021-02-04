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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include "asinfo.h"
#include "globals.h"

static struct __res_state res;

static const char *asinfo_from_ipv4(const char *, char **, char **);
#ifdef asinfo_ipv6
static const char *asinfo_from_ipv6(const char *, char **, char **);
#endif
static const char *asinfo_from_dns(const char *, char **, char **);
static const char *keep_best(char **, char **, char *, char *);

const char *
asinfo_from_rr(const char *rrtype, const char *rdata,
	       char **asnum, char **cidr)
{
	if (asinfo_lookup) {
		if (strcmp(rrtype, "A") == 0)
			return asinfo_from_ipv4(rdata, asnum, cidr);
#ifdef asinfo_ipv6
		if (strcmp(rrtype, "AAAA") == 0)
			return asinfo_from_ipv6(rdata, asnum, cidr);
#endif
	}
	return NULL;
}

static const char *
asinfo_from_ipv4(const char *addr, char **asnum, char **cidr) {
	u_char a4[32/8];
	char *dname;

	if (inet_pton(AF_INET, addr, a4) < 0)
		return strerror(errno);
	int n = asprintf(&dname, "%d.%d.%d.%d.%s",
			 a4[3], a4[2], a4[1], a4[0], asinfo_domain);
	if (n < 0)
		return strerror(errno);
	const char *result = asinfo_from_dns(dname, asnum, cidr);
	free(dname);
	return result;
}

#ifdef asinfo_ipv6
static const char *
asinfo_from_ipv6(const char *addr, char **asnum, char **cidr) {
	u_char a6[128/8];
	const char *result;
	char *dname, *p;
	int i;

	if (inet_pton(AF_INET6, addr, &a6) < 0)
		return strerror(errno);
	dname = malloc(strlen(asinfo_domain) + (128/4)*2);
	if (dname == NULL)
		return strerror(errno);
	result = NULL;
	p = dname;
	for (i = (128/8) - 1; i >= 0; i--) {
		int n = sprintf(p, "%x.%x.", a6[i] & 0xf, a6[i] >> 4);
		if (n < 0) {
			result = strerror(errno);
			break;
		}
		p += n;
	}
	if (result == NULL) {
		strcpy(p, asinfo_domain);
		result = asinfo_from_dns(dname, asnum, cidr);
	}
	p = NULL;
	free(dname);
	return result;
}
#endif

static const char *
asinfo_from_dns(const char *dname, char **asnum, char **cidr) {
	u_char buf[NS_PACKETSZ];
	int n, an, rrn, rcode;
	const char *result;
	ns_msg msg;
	ns_rr rr;

	DEBUG(1, true, "asinfo_from_dns(%s)\n", dname);
	if ((res.options & RES_INIT) == 0) {
		res_ninit(&res);
		/* use a TCP connection and keep it open */
		res.options |= RES_USEVC|RES_STAYOPEN;
	}
	n = res_nquery(&res, dname, ns_c_in, ns_t_txt, buf, sizeof buf);
	if (n < 0)
		return hstrerror(_res.res_h_errno);
	if (ns_initparse(buf, n, &msg) < 0)
		return strerror(errno);
	rcode = ns_msg_getflag(msg, ns_f_rcode);
	if (rcode != ns_r_noerror)
		return p_rcode(rcode);
	an = ns_msg_count(msg, ns_s_an);
	if (an == 0)
		return "ANCOUNT == 0";
	result = NULL;
	for (rrn = 0; result == NULL && rrn < an; rrn++) {
		const u_char *rdata;
		int rdlen, ntxt;
		char *txt[3];

		if (ns_parserr(&msg, ns_s_an, rrn, &rr) < 0) {
			result = strerror(errno);
			break;
		}
		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);
		ntxt = 0;
		while (rdlen > 0) {
			if (ntxt == 3) {
				result = "len(TXT[]) > 3";
				break;
			}
			n = *rdata++;
			rdlen--;
			if (n > rdlen) {
				result = "TXT overrun";
				break;
			}
			txt[ntxt] = strndup((const char *)rdata, (size_t)n);
			if (txt[ntxt] == NULL) {
				result = "strndup FAIL";
				break;
			}
			DEBUG(2, true, "TXT[%d] \"%s\"\n", ntxt, txt[ntxt]);
			rdata += n;
			rdlen -= n;
			ntxt++;
		}

		if (result == NULL) {
			const int seplen = sizeof " | " - 1;
			const char *t1 = NULL, *t2 = NULL;

			if (ntxt == 1 &&
			    (t1 = strstr(txt[0], " | ")) != NULL &&
			    (t2 = strstr(t1 + seplen, " | ")) != NULL)
			{
				/* team-cymru.com format. */
				char *new_asnum, *new_cidr;
				new_asnum = strndup(txt[0], (size_t)
						    (t1 - txt[0]));
				new_cidr = strndup(t1 + seplen, (size_t)
						   (t2 - (t1 + seplen)));
				t1 = t2 = NULL;
				result = keep_best(asnum, cidr,
						   new_asnum, new_cidr);
			} else if (ntxt == 3) {
				/* routeviews.org format. */
				char *new_asnum, *new_cidr;
				if (asprintf(&new_cidr, "%s/%s",
					     txt[1], txt[2]) >= 0)
				{
					new_asnum = strdup(txt[0]);
					result = keep_best(asnum, cidr,
							   new_asnum,
							   new_cidr);
				} else {
					result = strerror(errno);
				}
			} else {
				result = "unrecognized asinfo TXT format";
			}
		}
		for (n = 0; n < ntxt; n++) {
			free(txt[n]);
			txt[n] = NULL;
		}
	}
	return result;
}

static const char *
keep_best(char **asnum, char **cidr, char *new_asnum, char *new_cidr) {
	if (*asnum != NULL && *cidr != NULL) {
		int pfxlen, new_pfxlen;
		char *cp;

		if ((cp = strchr(*asnum, '/')) == NULL ||
		    (pfxlen = atoi(cp+1)) <= 0 || pfxlen > 128)
			return "bad CIDR syntax";
		if ((cp = strchr(new_asnum, '/')) == NULL ||
		    (new_pfxlen = atoi(cp+1)) <= 0 || new_pfxlen > 128)
			return "bad CIDR syntax";
		if (new_pfxlen <= pfxlen) {
			free(new_asnum);
			free(new_cidr);
			return NULL;
		}
		free(*asnum);
		*asnum = NULL;
		free(*cidr);
		*cidr = NULL;
	}
	if (strcmp(new_asnum, "4294967295") == 0) {
		/* in routeviews.org, this is how they signal "unknown". */
		free(new_asnum);
		free(new_cidr);
	} else {
		*asnum = new_asnum;
		*cidr = new_cidr;
	}
	return NULL;
}

void
asinfo_shutdown(void) {
	if ((res.options & RES_INIT) != 0)
		res_nclose(&res);
}
