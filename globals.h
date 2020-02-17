#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED 1

#ifndef MAIN_PROGRAM
#define EXTERN
#define INIT(x) = x
#else
#define EXTERN extern
#define INIT(x)
#endif

#ifndef MAIN_PROGRAM
extern const struct verb verbs[];
#endif

EXTERN	const char id_swclient[]	INIT("dnsdbq");
EXTERN	const char id_version[]		INIT("1.999");
EXTERN	const char *program_name	INIT(NULL);
EXTERN	verb_t chosen_verb		INIT(&verbs[DEFAULT_VERB]);
EXTERN	pdns_system_ct sys		INIT(NULL);
EXTERN	const char path_sort[]		INIT("/usr/bin/sort");
EXTERN	const char json_header[]	INIT("Accept: application/json");
EXTERN	const char env_time_fmt[]	INIT("DNSDBQ_TIME_FORMAT");

#undef INIT
#undef EXTERN

void debug(bool, const char *, ...);
__attribute__((noreturn)) void usage(const char *, ...);
__attribute__((noreturn)) void my_exit(int);
__attribute__((noreturn)) void my_panic(bool, const char *);

#endif /*GLOBALS_H_INCLUDED*/
