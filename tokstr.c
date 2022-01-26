// tokstr -- textual token iterator with some input independence
// 2022-01-25 [initially released inside dnsdbq]

/* externals. */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "tokstr.h"

/* private data types. */

enum tokstr_type { ts_buffer, ts_string };

struct tokstr_class {
	enum tokstr_type	type;
};

struct tokstr_buffer {
	struct tokstr_class	class;
	const char		*source;
	size_t			size;
};

struct tokstr_string {
	struct tokstr_class	class;
	const char		*source;
};

struct tokstr {
	union {
		struct tokstr_class	class;
		struct tokstr_buffer	buffer;
		struct tokstr_string	string;
	} data;
};

/* forward. */

static char *next_buffer(struct tokstr_buffer *, const char *);
static char *next_string(struct tokstr_string *, const char *);

/* public. */

tokstr_t
tokstr_buffer(const char *source, size_t size) {
	tokstr_t ts = malloc(sizeof(struct tokstr_buffer));
	if (ts != NULL) {
		ts->data.buffer = (struct tokstr_buffer) {
			.class = (struct tokstr_class) {
				.type = ts_buffer,
				},
			.source = source,
			.size = size,
		};
	}
	return ts;
}

tokstr_t
tokstr_string(const char *source) {
	tokstr_t ts = malloc(sizeof(struct tokstr_string));
	if (ts != NULL) {
		ts->data.string = (struct tokstr_string) {
			.class = (struct tokstr_class) {
				.type = ts_string,
				},
			.source = source,
		};
	}
	return ts;
}

char *
tokstr_next(tokstr_t ts, const char *delims) {
	char *ret = NULL;
	switch (ts->data.class.type) {
	case ts_buffer:
		ret = next_buffer(&ts->data.buffer, delims);
		break;
	case ts_string:
		ret = next_string(&ts->data.string, delims);
		break;
	default:
		abort();
	}
	return ret;
}

void
tokstr_last(tokstr_t *pts) {
	free(*pts);
	*pts = NULL;
}

/* private functions. */

static char *
next_buffer(struct tokstr_buffer *buf, const char *delims) {
	char *ret = NULL;
	if (buf->size != 0) {
		while (buf->size != 0 && strchr(delims, *buf->source) != 0)
			buf->size--, buf->source++;
		const char *prev = buf->source;
		while (buf->size != 0 && strchr(delims, *buf->source) == 0)
			buf->size--, buf->source++;
		size_t size = (size_t) (buf->source - prev);
		if (size != 0)
			ret = strndup(prev, size);
	}
	return ret;
}

static char *
next_string(struct tokstr_string *str, const char *delims) {
	char *ret = NULL;
	int ch = *str->source;
	if (ch != '\0') {
		while (ch != '\0' && strchr(delims, ch) != NULL)
			ch = *++str->source;
		const char *next = str->source;
		while (ch != '\0' && strchr(delims, ch) == NULL)
			ch = *++next;
		size_t size = (size_t) (next - str->source);
		if (size != 0)
			ret = strndup(str->source, size);
		str->source = next;
	}
	return ret;
}
