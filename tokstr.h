#ifndef __TOKSTR_H
#define __TOKSTR_H

// tokstr -- textual token iterator with some input independence
// 2022-01-29 [revised during code review, add regions]
// 2022-01-25 [initially released inside dnsdbq]

/* example using heap-allocated strings:

	tokstr_t ts = tokstr_string("this:is+-test");
	for (char *t; (t = tokstr_next(ts, "-:+")) != NULL; free(t))
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * will output "this", "is", and "test". so will this:

	tokstr_t ts = tokstr_string("this:is+-test");
	for (char t[100]; tokstr_next_copy(ts, "-:+", t, sizeof t) > 0;)
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * as will this:

	tokstr_t ts = tokstr_string("this:is+-test");
	for (;;) {
		struct tokstr_reg t = tokstr_next_region(ts, "-:+");
		if (t.base == NULL)
			break;
		printf("\t\"%*s\"\n", t.size, t.base);
	}
	tokstr_last(&ts);

 */

// tokstr_t -- opaque handle for one iterator
struct tokstr;
typedef struct tokstr *tokstr_t;

struct tokstr_reg {
	const char		*base;
	size_t			size;
};

// tokstr_region -- create an iterator for a counted string
tokstr_t tokstr_region(struct tokstr_reg);

// tokstr_string -- create an iterator for a nul-terminated string
tokstr_t tokstr_string(const char *);

// tokstr_next -- return next token from an iterator (caller must free() this)
char *tokstr_next(tokstr_t, const char *);

// tokstr_next_copy -- copy next token from an iterator; return size, 0, or -1
ssize_t tokstr_next_copy(tokstr_t, const char *, char *, size_t);

// tokstr_next_region -- return region of next token
struct tokstr_reg tokstr_next_region(tokstr_t, const char *);

// tokstr_last -- destroy an iterator and release all of its internal resources
void tokstr_last(tokstr_t *);

#endif /*__TOKSTR_H*/
