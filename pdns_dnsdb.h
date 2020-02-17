char *dnsdb_url(const char *, char *);
void dnsdb_request_info(void);
void dnsdb_write_info(reader_t);
void dnsdb_auth(reader_t);
const char *dnsdb_status(reader_t);
const char *dnsdb_validate_verb(const char *);

