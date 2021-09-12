#ifndef __DEDUPER_H_INCLUDED
#define __DEDUPER_H_INCLUDED 1

struct deduper;
typedef struct deduper *deduper_t;

deduper_t deduper_new(size_t);
bool deduper_tas(deduper_t, const char *);
void deduper_dump(deduper_t, FILE *);
void deduper_destroy(deduper_t *);

#endif /*__DEDUPER_H_INCLUDED*/
