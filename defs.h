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
