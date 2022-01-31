#ifndef __TOKSTR_H
#define __TOKSTR_H

// tokstr -- textual token iterator with some input independence
// 2022-01-25 [initially released inside dnsdbq]

/* example:

	tokstr_t ts = tokstr_string("this:is+-test");
	for (char *t; (t = tokstr_next(ts, "-:+")) != NULL; free(t))
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * will output "this", "is", and "test".
 */

// opaque type for iterator state -- never used
struct tokstr;

// tokstr_buffer -- create an iterator for a counted string
struct tokstr *tokstr_buffer(const char *, size_t);

// tokstr_string -- create an iterator for a nul-terminated string
struct tokstr *tokstr_string(const char *);

// tokstr_next -- return next token from an iterator (caller must free() this)
char *tokstr_next(struct tokstr *, const char *);

// tokstr_last -- destroy an iterator and release all of its internal resources
void tokstr_last(struct tokstr **);

#endif /*__TOKSTR_H*/
