#if WANT_PDNS_CIRCL

static char *circl_url(const char *, char *);
static void circl_auth(reader_t);
static const char *circl_status(reader_t);
static const char *circl_verb_ok(const char *);

static char *circl_base_url = NULL;
static char *circl_authinfo = NULL;

static const struct pdns_sys circl = {
	"circl", "https://www.circl.lu/pdns/query",
	circl_url, NULL, NULL,
	circl_auth, circl_status, circl_verb_ok,
	circl_ready, circl_destroy
};

pdns_sys_t
pdns_circl(void) {
	return &circl;
}

void
circl_destroy(void) {
	DESTROY(circl_base_url);
	DESTROY(circl_authinfo);
}

/* circl_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 *
 * CIRCL pDNS only "understands IP addresses, hostnames or domain names
 * (please note that CIDR block queries are not supported)". exit with an
 * error message if asked to do something the CIRCL server does not handle.
 *
 * 1. RRSet query: rrset/name/NAME[/TYPE[/BAILIWICK]]
 * 2. Rdata (name) query: rdata/name/NAME[/TYPE]
 * 3. Rdata (IP address) query: rdata/ip/ADDR[/PFXLEN]
 */
static char *
circl_url(const char *path, char *sep) {
	const char *val = NULL;
	char *ret;
	int x, pi;
	/* NULL-terminate array of valid query paths for CIRCL */
	const char *valid_paths[] =
		{ "rrset/name/", "rdata/name/", "rdata/ip/", NULL };

	if (circl_base_url == NULL)
		circl_base_url = strdup(sys->base_url);

	for (pi = 0; valid_paths[pi] != NULL; pi++)
		if (strncasecmp(path, valid_paths[pi], strlen(valid_paths[pi]))
		    == 0)
		{
			val = path + strlen(valid_paths[pi]);
			break;
		}
	if (val == NULL) {
		fprintf(stderr,
			"%s: unsupported type of query for CIRCL pDNS: %s\n",
			program_name, path);
		my_exit(1);
	}

	if (strchr(val, '/') != NULL) {
		fprintf(stderr,
			"%s: qualifiers not supported by CIRCL pDNS: %s\n",
			program_name, val);
		my_exit(1);
	}
	x = asprintf(&ret, "%s/%s", circl_base_url, val);
	if (x < 0)
		my_panic(true, "asprintf");

	/* because we will NOT append query parameters,
	 * tell the caller to use ? for its query parameters.
	 */
	if (sep != NULL)
		*sep = '?';

	return (ret);
}

static void
circl_auth(reader_t reader) {
	if (reader->easy != NULL) {
		curl_easy_setopt(reader->easy, CURLOPT_USERPWD,
				 circl_authinfo);
		curl_easy_setopt(reader->easy, CURLOPT_HTTPAUTH,
				 CURLAUTH_BASIC);
	}
}

static const char *
circl_status(reader_t reader __attribute__((unused))) {
	return "ERROR";
}

static const char *
circl_verb_ok(const char *verb_name) {
	/* Only "lookup" is valid */
	if (strcasecmp(verb_name, "lookup") != 0)
		return ("the CIRCL system only understands 'lookup'");
	return (NULL);
}

#endif /*WANT_PDNS_CIRCL*/
