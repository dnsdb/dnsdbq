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

#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED 1

#include "defs.h"
#include "sort.h"

#ifdef MAIN_PROGRAM
#define EXTERN
#define INIT(...) = __VA_ARGS__
#else
#define EXTERN extern
#define INIT(...)
#endif

#ifndef MAIN_PROGRAM
extern const struct verb verbs[];
#endif

EXTERN	const char id_swclient[]	INIT("dnsdbq");
EXTERN	const char id_version[]		INIT("2.5.6");
EXTERN	const char *program_name	INIT(NULL);
EXTERN	const char path_sort[]		INIT("/usr/bin/sort");
EXTERN	const char json_header[]	INIT("Accept: application/json");
EXTERN	const char jsonl_header[]	INIT("Accept: application/x-ndjson");
EXTERN	const char env_time_fmt[]	INIT("DNSDBQ_TIME_FORMAT");
EXTERN	const char env_config_file[]	INIT("DNSDBQ_CONFIG_FILE");
EXTERN	const char status_noerror[]	INIT("NOERROR");
EXTERN	const char status_error[]	INIT("ERROR");
EXTERN	const char *asinfo_domain	INIT("asn.routeviews.org");
EXTERN	struct qparam qparam_empty INIT({ .query_limit = -1L,
			.explicit_output_limit = -1L, .output_limit = -1L });
EXTERN	char *config_file		INIT(NULL);
EXTERN	verb_ct pverb			INIT(NULL);
EXTERN	pdns_system_ct psys		INIT(NULL);
EXTERN	int debug_level			INIT(0);
EXTERN	bool asinfo_lookup		INIT(false);
EXTERN	bool donotverify		INIT(false);
EXTERN	bool quiet			INIT(false);
EXTERN	bool iso8601			INIT(false);
EXTERN	bool multiple			INIT(false);
EXTERN	bool psys_specified		INIT(false);
EXTERN	int transforms			INIT(0);
EXTERN	long max_count			INIT(0L);
EXTERN	sort_e sorting			INIT(no_sort);
EXTERN	batch_e batching		INIT(batch_none);
EXTERN	present_e presentation		INIT(pres_text);
EXTERN	present_t presenter		INIT(NULL);
EXTERN	struct timeval startup_time	INIT({});
EXTERN	int exit_code			INIT(0);
EXTERN	long curl_ipresolve		INIT(CURL_IPRESOLVE_WHATEVER);

#undef INIT
#undef EXTERN

__attribute__((noreturn)) void my_exit(int);
__attribute__((noreturn)) void my_panic(bool, const char *);

#endif /*GLOBALS_H_INCLUDED*/
