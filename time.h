#ifndef TIME_H_INCLUDED
#define TIME_H_INCLUDED 1

#include <sys/types.h>
#include <stdbool.h>

int time_cmp(u_long, u_long);
const char * time_str(u_long, bool);
int time_get(const char *src, u_long *dst);

#endif /*TIME_H_INCLUDED*/
