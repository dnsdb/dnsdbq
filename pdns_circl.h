#if WANT_PDNS_CIRCL
/* CIRCL specific Forward. */

static char *circl_url(const char *, char *);
static void circl_auth(reader_t);
static const char *circl_status(reader_t);
static const char *circl_validate_verb(const char *);
#endif
