/*
 * Copyright (c) 2021 by Farsight Security, Inc.
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

#ifndef __DEDUPER_H_INCLUDED
#define __DEDUPER_H_INCLUDED 1

struct deduper;
typedef struct deduper *deduper_t;

deduper_t deduper_new(size_t);
bool deduper_tas(deduper_t, const char *);
void deduper_dump(deduper_t, FILE *);
void deduper_destroy(deduper_t *);

#endif /*__DEDUPER_H_INCLUDED*/
