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

#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include "globals.h"
#include "pdns_asn.h"

static const char *asn_from_ipv4(const char *, char **, char **);
static const char *asn_from_dns(const char *, char **, char **);

const char *
asn_from_rr(const char *rrtype, const char *rdata, char **asn, char **cidr) {
	if (asn_lookup) {
		if (strcmp(rrtype, "A") == 0)
			return asn_from_ipv4(rdata, asn, cidr);
	}
	return NULL;
}

static const char *
asn_from_ipv4(const char *addr, char **asn, char **cidr) {
	int a1, a2, a3, a4;
	char *dname;

	if (sscanf(addr, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) != 4)
		return "bad ipv4 rdata pattern (sscanf failed)";
	if (asprintf(&dname, "%d.%d.%d.%d.%s", a4, a3, a2, a1, asn_domain) < 0)
		return strerror(errno);
	const char *result = asn_from_dns(dname, asn, cidr);
	free(dname);
	return result;
}

static const char *
asn_from_dns(const char *dname, char **asn, char **cidr) {
	const u_char *rdata, *end;
	int n, an, ntxt, rcode;
	u_char buf[NS_MAXMSG];
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
	if (result != NULL) {
		for (n = 0; n < ntxt; n++) {
			free(txt[n]);
			txt[n] = NULL;
		}
		return result;
	}
	*asn = strdup(txt[0]);
	asprintf(cidr, "%s/%s", txt[1], txt[2]);
	return NULL;
}
