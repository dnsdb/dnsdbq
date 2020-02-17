/* conforms to the fields in the IETF passive DNS COF draft
 * except for num_results which is an addition for summarize.
 */
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

/* presentation formatter function for a passive DNS tuple */
typedef void (*present_t)(pdns_tuple_ct, const char *, size_t, FILE *);

void present_text(pdns_tuple_ct, const char *, size_t, FILE *);
void present_json(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv_line(pdns_tuple_ct, const char *, FILE *);
void present_text_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
void present_json_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
void present_csv_summarize(pdns_tuple_ct, const char *, size_t, FILE *);
const char *tuple_make(pdns_tuple_t, const char *, size_t);
void tuple_unmake(pdns_tuple_t);
