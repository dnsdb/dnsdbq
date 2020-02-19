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

#include <string.h>

#define DEFAULT_SYS 0
#define DEFAULT_VERB 0
#define	MAX_JOBS 8

#define CREATE(p, s) if ((p) != NULL) { my_panic(false, "non-NULL ptr"); } \
	else if (((p) = malloc(s)) == NULL) { my_panic(true, "malloc"); } \
	else { memset((p), 0, s); }
#define DESTROY(p) { if ((p) != NULL) { free(p); (p) = NULL; } }
#define DEBUG(ge, ...) { if (debug_level >= (ge)) debug(__VA_ARGS__); }

typedef enum { text, json, csv } present_e;
typedef enum { batch_none, batch_original, batch_verbose } batch_e;

#endif /*DEFS_H_INCLUDED*/
