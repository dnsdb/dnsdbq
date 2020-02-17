#ifndef SORT_H_INCLUDED
#define SORT_H_INCLUDED 1

struct sortbuf { char *base; size_t size; };
typedef struct sortbuf *sortbuf_t;

struct sortkey { char *specified, *computed; };
typedef struct sortkey *sortkey_t;
typedef const struct sortkey *sortkey_ct;

typedef enum { no_sort = 0, normal_sort, reverse_sort } sort_e;

const char *add_sort_key(const char *);
sortkey_ct find_sort_key(const char *);
void sort_ready(void);
void sort_destroy(void);
void exec_sort(int p1[], int p2[]);
char *sortable_rrname(pdns_tuple_ct);
char *sortable_rdata(pdns_tuple_ct);
void sortable_rdatum(sortbuf_t, const char *, const char *);
void sortable_dnsname(sortbuf_t, const char *);
void sortable_hexify(sortbuf_t, const u_char *, size_t);

#endif /*SORT_H_INCLUDED*/
