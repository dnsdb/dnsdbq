#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "deduper.h"

struct chainlink;
typedef struct chainlink *chainlink_t;

struct chainlink {
	chainlink_t next;
	char str[];
};
static inline size_t chainlink_size(size_t length) {
	return sizeof(struct chainlink) + length + 1;
}

struct deduper {
	size_t buckets;
	chainlink_t chains[];
};
static inline size_t deduper_size(size_t buckets) {
	return sizeof(struct deduper) + buckets * sizeof(chainlink_t);
}

static unsigned long hash_djb2(const char *);

deduper_t deduper_new(size_t buckets) {
	deduper_t ret = malloc(deduper_size(buckets));
	if (ret == NULL)
		abort();
	memset(ret, 0x00, deduper_size(buckets));
	ret->buckets = buckets;
	return ret;
}

bool deduper_tas(deduper_t me, const char *str) {
	size_t bucket = hash_djb2(str) % me->buckets;
	chainlink_t chainlink;
	for (chainlink = me->chains[bucket];
	     chainlink != NULL;
	     chainlink = chainlink->next)
		if (strcmp(str, chainlink->str) == 0)
			return true;
	size_t len = strlen(str);
	chainlink = malloc(chainlink_size(len));
	if (chainlink == NULL)
		abort();
	memset(chainlink, 0, chainlink_size(len));
	chainlink->next = me->chains[bucket];
	strcpy(chainlink->str, str);
	me->chains[bucket] = chainlink;
	return false;
}

void
deduper_dump(deduper_t me, FILE *out) {
	for (size_t bucket = 0; bucket < me->buckets; bucket++)
		if (me->chains[bucket] != NULL) {
			fprintf(out, "[%lu]", bucket);
			for (chainlink_t chainlink = me->chains[bucket];
			     chainlink != NULL;
			     chainlink = chainlink->next)
				fprintf(out, " \"%s\"", chainlink->str);
			fprintf(out, ".\n");
		}
}

void
deduper_destroy(deduper_t *me) {
	for (size_t bucket = 0; bucket < (*me)->buckets; bucket++) {
		chainlink_t next = (*me)->chains[bucket];
		if (next != NULL) {
			for (chainlink_t chainlink = next;
			     chainlink != NULL;
			     chainlink = next) {
				next = chainlink->next;
				chainlink->next = NULL;
				free(chainlink);
			}
			(*me)->chains[bucket] = NULL;
		}
	}
	memset(*me, 0, deduper_size((*me)->buckets));
	free(*me);
	*me = NULL;
}

static unsigned long
hash_djb2(const char *str) {
	unsigned long hash = 5381;
	unsigned int c;

	while ((c = (unsigned char) *str++) != '\0')
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}
