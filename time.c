/* time_cmp -- compare two absolute timestamps, give -1, 0, or 1.
 */
int
time_cmp(u_long a, u_long b) {
	if (a < b)
		return (-1);
	if (a > b)
		return (1);
	return (0);
}

/* time_str -- format one (possibly relative) timestamp (returns static string)
 */
const char *
time_str(u_long x, bool iso8601fmt) {
	static char ret[sizeof "yyyy-mm-ddThh:mm:ssZ"];

	if (x == 0) {
		strcpy(ret, "0");
	} else {
		time_t t = (time_t)x;
		struct tm result, *y = gmtime_r(&t, &result);

		strftime(ret, sizeof ret, iso8601fmt ? "%FT%TZ" : "%F %T", y);
	}
	return ret;
}

/* time_get -- parse and return one (possibly relative) timestamp.
 */
int
time_get(const char *src, u_long *dst) {
	struct tm tt;
	long long ll;
	u_long t;
	char *ep;

	memset(&tt, 0, sizeof tt);
	if (((ep = strptime(src, "%F %T", &tt)) != NULL && *ep == '\0') ||
	    ((ep = strptime(src, "%F", &tt)) != NULL && *ep == '\0'))
	{
		*dst = (u_long)(timegm(&tt));
		return (1);
	}
	ll = strtoll(src, &ep, 10);
	if (*src != '\0' && *ep == '\0') {
		if (ll < 0)
			*dst = (u_long)now.tv_sec - (u_long)imaxabs(ll);
		else
			*dst = (u_long)ll;
		return (1);
	}
	if (ns_parse_ttl(src, &t) == 0) {
		*dst = (u_long)now.tv_sec - t;
		return (1);
	}
	return (0);
}

