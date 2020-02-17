#ifndef PDNS_H_INCLUDED
#define PDNS_H_INCLUDED 1

struct pdns_json {
	json_t	*main,
		*time_first, *time_last, *zone_first, *zone_last,
		*bailiwick, *rrname, *rrtype, *rdata,
		*count, *num_results;
};

struct pdns_tuple {
	struct pdns_json  obj;
	u_long		  time_first, time_last, zone_first, zone_last;
	const char	 *bailiwick, *rrname, *rrtype, *rdata;
	json_int_t	  count, num_results;
};
typedef struct pdns_tuple *pdns_tuple_t;
typedef const struct pdns_tuple *pdns_tuple_ct;

struct pdns_system {
	const char	*name;
	const char	*base_url;
	char *		(*url)(const char *, char *);
	void		(*request_info)(void);
	void		(*write_info)(reader_t);
	void		(*auth)(reader_t);
	const char *	(*status)(reader_t);
	const char *	(*verb_ok)(const char *);
	void		(*ready)(void);
	void		(*destroy)(void);
};
typedef const struct pdns_system *pdns_system_ct;

typedef void (*present_t)(pdns_tuple_ct, const char *, size_t, FILE *);

typedef enum { no_mode = 0, rrset_mode, name_mode, ip_mode,
	       raw_rrset_mode, raw_name_mode } mode_e;

struct query {
	mode_e	mode;
	char	*thing;
	char	*rrtype;
	char	*bailiwick;
	char	*pfxlen;
	u_long	after;
	u_long	before;
};
typedef struct query *query_t;
typedef const struct query *query_ct;

void present_text(pdns_tuple_ct, const char *, size_t, FILE *);
void present_json(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv_line(pdns_tuple_ct, const char *, FILE *);
void present_text_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
void present_json_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
const char *tuple_make(pdns_tuple_t, const char *, size_t);
void tuple_unmake(pdns_tuple_t);
int input_blob(const char *, size_t, u_long, u_long, FILE *);

#endif /*PDNS_H_INCLUDED*/
