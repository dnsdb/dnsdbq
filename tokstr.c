// tokstr -- textual token iterator with some input independence
// 2022-01-29 [revised during code review, add regions]
// 2022-01-25 [initially released inside dnsdbq]

/* externals. */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "tokstr.h"

/* private data types. */

enum tokstr_type { ts_buffer, ts_string };

struct tokstr_class {
	enum tokstr_type	type;
};

struct tokstr_region {
	struct tokstr_class	class;
	struct tokstr_reg	source;
};

struct tokstr_string {
	struct tokstr_class	class;
	const char		*source;
};

struct tokstr_pvt {
	union {
		struct tokstr_class	class;
		struct tokstr_region	region;
		struct tokstr_string	string;
	} data;
};

/* forward. */

static struct tokstr_reg next_region(struct tokstr_region *, const char *);
static struct tokstr_reg next_string(struct tokstr_string *, const char *);

/* public. */

// tokstr_region -- create an iterator for a counted string
struct tokstr *
tokstr_region(struct tokstr_reg source) {
	struct tokstr_region *ts = malloc(sizeof(struct tokstr_region));
	if (ts != NULL) {
		*ts = (struct tokstr_region) {
			.class = (struct tokstr_class) {
				.type = ts_buffer,
				},
			.source = source,
		};
	}
	return (struct tokstr *) ts;
}

// tokstr_string -- create an iterator for a nul-terminated string
struct tokstr *
tokstr_string(const char *source) {
	struct tokstr_string *ts = malloc(sizeof(struct tokstr_string));
	if (ts != NULL) {
		*ts = (struct tokstr_string) {
			.class = (struct tokstr_class) {
				.type = ts_string,
				},
			.source = source,
		};
	}
	return (struct tokstr *) ts;
}

// tokstr_next -- return next token from an iterator (strndup)
char *
tokstr_next(struct tokstr *ts_pub, const char *delims) {
	struct tokstr_reg reg = tokstr_next_region(ts_pub, delims);
	if (reg.base == NULL)
		return NULL;
	return strndup(reg.base, reg.size);
}

// tokstr_next_region -- return next token from an iterator (zero-copy)
struct tokstr_reg
tokstr_next_region(struct tokstr *ts_pub, const char *delims) {
	struct tokstr_pvt *ts = (struct tokstr_pvt *) ts_pub;
	struct tokstr_reg reg = {};
	switch (ts->data.class.type) {
	case ts_buffer:
		reg = next_region(&ts->data.region, delims);
		break;
	case ts_string:
		reg = next_string(&ts->data.string, delims);
		break;
	default:
		abort();
	}
	assert((reg.base == NULL) == (reg.size == 0));
	return reg;
}

// tokstr_next_copy -- copy next token from an iterator; return size, 0, or -1
ssize_t
tokstr_next_copy(struct tokstr *ts, const char *delims,
		 char *buffer, size_t size)
{
	struct tokstr_reg reg = tokstr_next_region(ts, delims);
	if (reg.base == NULL)
		return 0;
	if (reg.size >= size) {
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(buffer, reg.base, reg.size);
	buffer[reg.size] = '\0';
	return (ssize_t) reg.size;
}

// tokstr_last -- destroy an iterator and release all of its internal resources
void
tokstr_last(struct tokstr **pts) {
	free(*pts);
	*pts = NULL;
}

/* private functions. */

// next_buffer -- implement tokstr_next for counted string iterators
static struct tokstr_reg
next_region(struct tokstr_region *reg, const char *delims) {
	if (reg->source.size != 0) {
		while (reg->source.size != 0 &&
		       strchr(delims, *reg->source.base) != 0)
			reg->source.size--, reg->source.base++;
		const char *prev = reg->source.base;
		while (reg->source.size != 0 &&
		       strchr(delims, *reg->source.base) == 0)
			reg->source.size--, reg->source.base++;
		size_t size = (size_t) (reg->source.base - prev);
		if (size != 0)
			return (struct tokstr_reg) {prev, size};
	}
	return (struct tokstr_reg) {};
}

// next_string -- implement tokstr_next for nul-terminated string iterators
static struct tokstr_reg
next_string(struct tokstr_string *str, const char *delims) {
	int ch = *str->source;
	if (ch != '\0') {
		while (ch != '\0' && strchr(delims, ch) != NULL)
			ch = *++str->source;
		const char *prev = str->source;
		while (ch != '\0' && strchr(delims, ch) == NULL)
			ch = *++str->source;
		size_t size = (size_t) (str->source - prev);
		if (size != 0)
			return (struct tokstr_reg) {prev, size};
	}
	return (struct tokstr_reg) {};
}
