#define	MAX_KEYS 5

static bool sort_byname = false;
static bool sort_bydata = false;
static struct sortkey keys[MAX_KEYS];
static int nkeys = 0;

/* sort_ready -- finish initializing the sort related metadata
 */
void
sort_ready(void) {
	/* if sorting, all keys must be specified, to enable -u. */
	(void) add_sort_key("first");
	(void) add_sort_key("last");
	(void) add_sort_key("count");
	(void) add_sort_key("name");
	(void) add_sort_key("data");
}

/* add_sort_key -- add a key for use by POSIX sort.
 */
const char *
add_sort_key(const char *tok) {
	const char *key = NULL;
	char *computed;
	int x;

	if (nkeys == MAX_KEYS)
		return ("too many sort keys given.");
	if (strcasecmp(tok, "first") == 0) {
		key = "-k1n";
	} else if (strcasecmp(tok, "last") == 0) {
		key = "-k2n";
	} else if (strcasecmp(tok, "count") == 0) {
		key = "-k3n";
	} else if (strcasecmp(tok, "name") == 0) {
		key = "-k4";
		sort_byname = true;
	} else if (strcasecmp(tok, "data") == 0) {
		key = "-k5";
		sort_bydata = true;
	}
	if (key == NULL)
		return ("key must be one of first, "
			"last, count, name, or data");
	x = asprintf(&computed, "%s%s", key,
		     sorted == reverse_sort ? "r" : "");
	if (x < 0)
		my_panic(true, "asprintf");
	keys[nkeys++] = (struct sortkey){strdup(tok), computed};
	return (NULL);
}

/* find_sort_key -- return pointer to a sort key, or NULL if it's not specified
 */
sortkey_ct
find_sort_key(const char *tok) {
	int n;

	for (n = 0; n < nkeys; n++) {
		if (strcmp(keys[n].specified, tok) == 0)
			return (&keys[n]);
	}
	return (NULL);
}

/* sort_destroy -- drop sort metadata from heap.
 */
void
sort_destroy(void) {
	int n;

	for (n = 0; n < nkeys; n++) {
		DESTROY(keys[n].specified);
		DESTROY(keys[n].computed);
	}
}

/* exec_sort -- replace this fork with a POSIX sort program
 */
void
exec_sort(int p1[], int p2[]) {
	char *sort_argv[3+MAX_KEYS], **sap;
	int n;

	if (dup2(p1[0], STDIN_FILENO) < 0 ||
	    dup2(p2[1], STDOUT_FILENO) < 0) {
		perror("dup2");
		_exit(1);
	}
	close(p1[0]); close(p1[1]);
	close(p2[0]); close(p2[1]);
	sap = sort_argv;
	*sap++ = strdup("sort");
	*sap++ = strdup("-u");
	for (n = 0; n < nkeys; n++)
		*sap++ = strdup(keys[n].computed);
	*sap++ = NULL;
	putenv(strdup("LC_ALL=C"));
	DEBUG(1, true, "\"%s\" args:", path_sort);
	for (sap = sort_argv; *sap != NULL; sap++)
		DEBUG(1, false, " [%s]", *sap);
	DEBUG(1, false, "\n");
	execve(path_sort, sort_argv, environ);
	perror("execve");
	for (sap = sort_argv; *sap != NULL; sap++)
		DESTROY(*sap);
	_exit(1);
}

/* sortable_rrname -- return a POSIX-sort-collatable rendition of RR name+type.
 */
char *
sortable_rrname(pdns_tuple_ct tup) {
	struct sortbuf buf = {NULL, 0};

	sortable_dnsname(&buf, tup->rrname);
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return (buf.base);
}

/* sortable_rdata -- return a POSIX-sort-collatable rendition of RR data set.
 */
char *
sortable_rdata(pdns_tuple_ct tup) {
	struct sortbuf buf = {NULL, 0};

	if (json_is_array(tup->obj.rdata)) {
		size_t slot, nslots;

		nslots = json_array_size(tup->obj.rdata);
		for (slot = 0; slot < nslots; slot++) {
			json_t *rr = json_array_get(tup->obj.rdata, slot);

			if (json_is_string(rr))
				sortable_rdatum(&buf, tup->rrtype,
						json_string_value(rr));
			else
				fprintf(stderr,
					"%s: warning: rdata slot "
					"is not a string\n",
					program_name);
		}
	} else {
		sortable_rdatum(&buf, tup->rrtype, tup->rdata);
	}
	buf.base = realloc(buf.base, buf.size+1);
	buf.base[buf.size++] = '\0';
	return (buf.base);
}

/* sortable_rdatum -- called only by sortable_rdata(), realloc and normalize.
 *
 * this converts (lossily) addresses into hex strings, and extracts the
 * server-name component of a few other types like MX. all other rdata
 * are left in their normal string form, because it's hard to know what
 * to sort by with something like TXT, and extracting the serial number
 * from an SOA using a language like C is a bit ugly.
 */
void
sortable_rdatum(sortbuf_t buf, const char *rrtype, const char *rdatum) {
	if (strcmp(rrtype, "A") == 0) {
		u_char a[4];

		if (inet_pton(AF_INET, rdatum, a) != 1)
			memset(a, 0, sizeof a);
		sortable_hexify(buf, a, sizeof a);
	} else if (strcmp(rrtype, "AAAA") == 0) {
		u_char aaaa[16];

		if (inet_pton(AF_INET6, rdatum, aaaa) != 1)
			memset(aaaa, 0, sizeof aaaa);
		sortable_hexify(buf, aaaa, sizeof aaaa);
	} else if (strcmp(rrtype, "NS") == 0 ||
		   strcmp(rrtype, "PTR") == 0 ||
		   strcmp(rrtype, "CNAME") == 0)
	{
		sortable_dnsname(buf, rdatum);
	} else if (strcmp(rrtype, "MX") == 0 ||
		   strcmp(rrtype, "RP") == 0)
	{
		const char *space = strrchr(rdatum, ' ');

		if (space != NULL)
			sortable_dnsname(buf, space+1);
		else
			sortable_hexify(buf, (const u_char *)rdatum,
					strlen(rdatum));
	} else {
		sortable_hexify(buf, (const u_char *)rdatum, strlen(rdatum));
	}
}

void
sortable_hexify(sortbuf_t buf, const u_char *src, size_t len) {
	size_t i;

	buf->base = realloc(buf->base, buf->size + len*2);
	for (i = 0; i < len; i++) {
		const char hex[] = "0123456789abcdef";
		unsigned int ch = src[i];

		buf->base[buf->size++] = hex[ch >> 4];
		buf->base[buf->size++] = hex[ch & 0xf];
	}
}

/* sortable_dnsname -- make a sortable dns name; destructive and lossy.
 *
 * to be lexicographically sortable, a dnsname has to be converted to
 * TLD-first, all uppercase letters must be converted to lower case,
 * and all characters except dots then converted to hexadecimal. this
 * transformation is for POSIX sort's use, and is irreversibly lossy.
 */
void
sortable_dnsname(sortbuf_t buf, const char *name) {
	const char hex[] = "0123456789abcdef";
	size_t len, new_size;
	unsigned int dots;
	signed int m, n;
	char *p;

	/* to avoid calling realloc() on every label, count the dots. */
	for (dots = 0, len = 0; name[len] != '\0'; len++) {
		if (name[len] == '.')
			dots++;
	}

	/* collatable names are TLD-first, all lower case. */
	new_size = buf->size + len*2 - (size_t)dots;
	assert(new_size != 0);
	if (new_size != buf->size)
		buf->base = realloc(buf->base, new_size);
	p = buf->base + buf->size;
	for (m = (int)len - 1, n = m; m >= 0; m--) {
		/* note: actual presentation form names can have \. and \\,
		 * but we are destructive and lossy, and will ignore that.
		 */
		if (name[m] == '.') {
			int i;

			for (i = m+1; i <= n; i++) {
				int ch = tolower(name[i]);
				*p++ = hex[ch >> 4];
				*p++ = hex[ch & 0xf];
			}
			*p++ = '.';
			n = m-1;
		}
	}
	assert(m == -1);
	/* first label remains after loop. */
	for (m = 0; m <= n; m++) {
		int ch = tolower(name[m]);
		*p++ = hex[ch >> 4];
		*p++ = hex[ch & 0xf];
	}
	buf->size = (size_t)(p - buf->base);
	assert(buf->size == new_size);
	/* if no characters were written, it's the empty string,
	 * meaning the dns root zone.
	 */
	if (len == 0) {
		buf->base = realloc(buf->base, buf->size + 1);
		buf->base[buf->size++] = '.';
	}
}
