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

#ifndef TIME_H_INCLUDED
#define TIME_H_INCLUDED 1

#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>

int time_cmp(u_long, u_long);
const char *time_str(u_long, bool);
const char *timeval_str(const struct timeval *, bool);
int time_get(const char *, u_long *);

#endif /*TIME_H_INCLUDED*/
