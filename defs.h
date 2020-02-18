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

struct verb {
	const char	*cmd_opt_val;
	const char	*url_fragment;
	/* validate_cmd_opts can review the command line options and exit
	 * if some verb-specific command line option constraint is not met.
	 */
	void		(*validate_cmd_opts)(void);
};
typedef const struct verb *verb_t;

#endif /*DEFS_H_INCLUDED*/
