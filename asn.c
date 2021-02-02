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
#include "asn.h"
#include "globals.h"

static const char *asinfo_from_ipv4(const char *, char **, char **);
static const char *asinfo_from_ipv6(const char *, char **, char **);
static const char *asinfo_from_dns(const char *, char **, char **);

const char *
asinfo_from_rr(const char *rrtype, const char *rdata,
	       char **asinfo, char **cidr)
{
	if (asinfo_lookup) {
		if (strcmp(rrtype, "A") == 0)
			return asinfo_from_ipv4(rdata, asinfo, cidr);
		if (strcmp(rrtype, "AAAA") == 0)
			return asinfo_from_ipv6(rdata, asinfo, cidr);
	}
	return NULL;
}

static const char *
asinfo_from_ipv4(const char *addr, char **asinfo, char **cidr) {
	u_char a4[32/8];
	char *dname;

	if (inet_pton(AF_INET, addr, a4) < 0)
		return strerror(errno);
	int n = asprintf(&dname, "%d.%d.%d.%d.%s",
			 a4[3], a4[2], a4[1], a4[0], asinfo_domain);
	if (n < 0)
		return strerror(errno);
	const char *result = asinfo_from_dns(dname, asinfo, cidr);
	free(dname);
	return result;
}

static const char *
asinfo_from_ipv6(const char *addr, char **asinfo, char **cidr) {
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
		result = asinfo_from_dns(dname, asinfo, cidr);
	}
	p = NULL;
	free(dname);
	return result;
}

static const char *
asinfo_from_dns(const char *dname, char **asinfo, char **cidr) {
	const u_char *rdata, *end;
	int n, an, ntxt, rcode;
	u_char buf[NS_PACKETSZ];
	const char *result;
	char *txt[3];
	ns_msg msg;
	ns_rr rr;

	n = res_query(dname, ns_c_in, ns_t_txt, buf, sizeof buf);
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
	if (an > 1)
		return "ANCOUNT > 1";
	if (ns_parserr(&msg, ns_s_an, 0, &rr) < 0)
		return strerror(errno);
	/* beyond this point, txt[] must be freed before returning. */
	rdata = ns_rr_rdata(rr);
	end = ns_msg_end(msg);
	ntxt = 0;
	result = NULL;
	while (end - rdata > 0) {
		if (ntxt == 3) {
			result = "len(TXT[]) > 3";
			break;
		}
		n = *rdata++;
		txt[ntxt] = strndup((const char *)rdata, (size_t)n);
		if (txt[ntxt] == NULL) {
			result = "strndup FAIL";
			break;
		}
		rdata += n;
		ntxt++;
	}
	if (result == NULL) {
		if (ntxt < 3)
			result = "len(TXT[] < 3";
	}
	if (result == NULL) {
		char *tmp;
		if (asprintf(&tmp, "%s/%s", txt[1], txt[2]) < 0) {
			result = strerror(errno);
		} else {
			*asinfo = strdup(txt[0]);
			*cidr = tmp;
			tmp = NULL;
		}
	}
	for (n = 0; n < ntxt; n++) {
		free(txt[n]);
		txt[n] = NULL;
	}
	return result;
}
