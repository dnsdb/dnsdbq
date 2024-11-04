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

#ifndef SORT_H_INCLUDED
#define SORT_H_INCLUDED 1

#include <sys/types.h>

#include "pdns.h"

struct sortbuf { char *base; size_t size; };
typedef struct sortbuf *sortbuf_t;

struct sortkey { char *specified, *computed; };
typedef struct sortkey *sortkey_t;
typedef const struct sortkey *sortkey_ct;

typedef enum { no_sort = 0, normal_sort, reverse_sort } sort_e;

const char *add_sort_key(const char *);
sortkey_ct find_sort_key(const char *);
void sort_ready(void);
void sort_destroy(void);
__attribute__((noreturn)) void exec_sort(int p1[], int p2[]);
char *sortable_rrname(pdns_tuple_ct);
char *sortable_rdata(pdns_tuple_ct);

#endif /*SORT_H_INCLUDED*/
