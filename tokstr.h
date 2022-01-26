#ifndef __TOKSTR_H
#define __TOKSTR_H

// tokstr -- textual token iterator with some input independence
// 2022-01-25 [initially released inside dnsdbq]

/* example:

	tokstr_h ts = tokstr_string("this:is+-test");
	for (char *t; (t = tokstr_next(ts, "-:+")) != NULL; free(t))
		printf("\t\"%s\"\n", t);
	tokstr_last(&ts);

 * will output "this", "is", and "test".
 */

// tokstr_t -- opaque handle for one iterator
struct tokstr;
typedef struct tokstr *tokstr_t;

// tokstr_buffer -- create an iterator for a counted string
tokstr_t tokstr_buffer(const char *source, size_t size);

// tokstr_string -- create an iterator for a nul-terminated string
tokstr_t tokstr_string(const char *source);

// tokstr_next -- return next token from an iterator (caller must free() this)
char *tokstr_next(tokstr_t ts, const char *delims);

// tokstr_last -- destroy an iterator and release all of its internal resources
void tokstr_last(tokstr_t *pts);

#endif /*__TOKSTR_H*/
