#ifndef __TOKSTR_H
#define __TOKSTR_H

// tokstr -- textual token iterator with some input independence
// 2022-01-29 [revised during code review, add regions]
// 2022-01-25 [initially released inside dnsdbq]

/* example using heap-allocated strings:

	struct tokstr *ts = tokstr_string("this:is+-test");
	for (char *t; (t = tokstr_next(ts, "-:+")) != NULL; free(t))
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * will output "this", "is", and "test". so will this:

	struct tokstr *ts = tokstr_string("this:is+-test");
	for (char t[100]; tokstr_next_copy(ts, "-:+", t, sizeof t) > 0;)
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * as will this:

	struct tokstr *ts = tokstr_string("this:is+-test");
	for (;;) {
		struct tokstr_reg t = tokstr_next_region(ts, "-:+");
		if (t.base == NULL)
			break;
		printf("\t\"%*s\"\n", t.size, t.base);
	}
	tokstr_last(&ts);

 */

// opaque type for iterator state -- never used
struct tokstr;

struct tokstr_reg {
	const char		*base;
	size_t			size;
};

// tokstr_region -- create an iterator for a counted string
struct tokstr *tokstr_region(struct tokstr_reg);

// tokstr_string -- create an iterator for a nul-terminated string
struct tokstr *tokstr_string(const char *);

// tokstr_string -- create an iterator for a nul-terminated string
struct tokstr *tokstr_string(const char *);

// tokstr_next -- return next token from an iterator (which must be free()'d)
char *tokstr_next(struct tokstr *, const char *);

// tokstr_next_copy -- return next token from an iterator (copy)
ssize_t tokstr_next_copy(struct tokstr *, const char *, char *, size_t);

// tokstr_next_region -- return next token from iterator (zero-copy)
struct tokstr_reg tokstr_next_region(struct tokstr *, const char *);

// tokstr_last -- destroy an iterator and release all of its internal resources
void tokstr_last(struct tokstr **);

#endif /*__TOKSTR_H*/
