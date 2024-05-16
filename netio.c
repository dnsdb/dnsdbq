/*
 * Copyright (c) 2014-2020 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "netio.h"
#include "pdns.h"
#include "globals.h"
#include "time.h"

static void io_drain(void);
static void fetch_reap(fetch_t);
static void fetch_done(fetch_t);
static void fetch_unlink(fetch_t);
static void last_fetch(fetch_t);

static writer_t writers = NULL;
static CURLM *multi = NULL;
static bool curl_cleanup_needed = false;
static query_t paused[MAX_FETCHES];
static int npaused = 0;

const char saf_begin[] = "begin";
const char saf_ongoing[] = "ongoing";
const char saf_succeeded[] = "succeeded";
const char saf_limited[] = "limited";
const char saf_failed[] = "failed";

const char *saf_valid_conds[] = {
	saf_begin, saf_ongoing, saf_succeeded, saf_limited, saf_failed
};

/* make_curl -- perform global initializations of libcurl.
 */
void
make_curl(void) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_cleanup_needed = true;
	multi = curl_multi_init();
	if (multi == NULL) {
		my_logf("curl_multi_init() failed");
		my_exit(1);
	}
}

/* unmake_curl -- clean up and discard libcurl's global state.
 */
void
unmake_curl(void) {
	if (multi != NULL) {
		curl_multi_cleanup(multi);
		multi = NULL;
	}
	if (curl_cleanup_needed) {
		curl_global_cleanup();
		curl_cleanup_needed = false;
	}
}

/* fetch -- given a url, tell libcurl to go fetch it, attach fetch to query.
 */
fetch_t
create_fetch(query_t query, char *url) {
	fetch_t fetch = NULL;
	CURLMcode res;

	DEBUG(2, true, "fetch(%s)\n", url);
	CREATE(fetch, sizeof *fetch);
	fetch->query = query;
	query = NULL;
	fetch->easy = curl_easy_init();
	if (fetch->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		DESTROY(fetch);
		DESTROY(url);
		my_exit(1);
	}
	fetch->url = url;
	url = NULL;
	curl_easy_setopt(fetch->easy, CURLOPT_URL, fetch->url);
	if (donotverify) {
		curl_easy_setopt(fetch->easy, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(fetch->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	/* if user specified a prefence for IPv4 or IPv6, use it. */
	if (curl_ipresolve != CURL_IPRESOLVE_WHATEVER)
		curl_easy_setopt(fetch->easy,
				 CURLOPT_IPRESOLVE, curl_ipresolve);

	/* if user specified a timeout, use for connection and transactions. */
	if (curl_timeout != 0L) {
		curl_easy_setopt(fetch->easy,
				 CURLOPT_CONNECTTIMEOUT, curl_timeout);
		curl_easy_setopt(fetch->easy,
				 CURLOPT_TIMEOUT, curl_timeout);
	}
	if (psys->auth != NULL)
	    psys->auth(fetch);

	/* if user specified a cookie file, tell libcurl about it. */
	if (cookie_file != NULL)
		curl_easy_setopt(fetch->easy, CURLOPT_COOKIEFILE, cookie_file);

	if (psys->encap == encap_saf)
		fetch->hdrs = curl_slist_append(fetch->hdrs, jsonl_header);
	else
		fetch->hdrs = curl_slist_append(fetch->hdrs, json_header);
	curl_easy_setopt(fetch->easy, CURLOPT_HTTPHEADER, fetch->hdrs);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEDATA, fetch);
	curl_easy_setopt(fetch->easy, CURLOPT_PRIVATE, fetch);
#ifdef CURL_AT_LEAST_VERSION
/* If CURL_AT_LEAST_VERSION is not defined then the curl is probably too old */
#if CURL_AT_LEAST_VERSION(7,42,0)
	/* do not allow curl to swallow /./ and /../ in our URLs */
	curl_easy_setopt(fetch->easy, CURLOPT_PATH_AS_IS, 1L);
#endif
#endif /* CURL_AT_LEAST_VERSION */
	if (debug_level >= 3)
		curl_easy_setopt(fetch->easy, CURLOPT_VERBOSE, 1L);

	/* linked-list insert. */
	fetch->next = fetch->query->fetches;
	fetch->query->fetches = fetch;

	res = curl_multi_add_handle(multi, fetch->easy);
	if (res != CURLM_OK) {
		my_logf("curl_multi_add_handle() failed: %s",
			curl_multi_strerror(res));
		my_exit(1);
	}
	return fetch;
}

/* fetch_reap -- reap one fetch.
 */
static void
fetch_reap(fetch_t fetch) {
	if (fetch->easy != NULL) {
		curl_multi_remove_handle(multi, fetch->easy);
		curl_easy_cleanup(fetch->easy);
		fetch->easy = NULL;
	}
	if (fetch->hdrs != NULL) {
		curl_slist_free_all(fetch->hdrs);
		fetch->hdrs = NULL;
	}
	DESTROY(fetch->saf_msg);
	DESTROY(fetch->url);
	DESTROY(fetch->buf);
	DESTROY(fetch);
}

/* fetch_done -- deal with consequences of end-of-fetch.
 */
static void
fetch_done(fetch_t fetch) {
	query_t query = fetch->query;

	/* if this was the last fetch on some query, signal. */
	if (query->fetches == fetch && fetch->next == NULL)
		last_fetch(fetch);
}

/* fetch_unlink -- disconnect a fetch from its writer.
 */
static void
fetch_unlink(fetch_t fetch) {
	fetch_t cur, prev;

	for (cur = fetch->query->fetches, prev = NULL;
	     cur != NULL && cur != fetch;
	     prev = cur, cur = cur->next) { }
	assert(cur == fetch);
	if (prev == NULL)
		fetch->query->fetches = fetch->next;
	else
		prev->next = fetch->next;
	fetch->query = NULL;
}

/* writer_init -- instantiate a writer, which may involve forking a "sort".
 */
writer_t
writer_init(long output_limit, ps_user_t ps_user, bool meta_query) {
	writer_t writer = NULL;

	CREATE(writer, sizeof(struct writer));
	writer->output_limit = output_limit;
	writer->ps_user = ps_user;
	writer->meta_query = meta_query;

	if (sorting != no_sort) {
		/* sorting involves a subprocess (POSIX sort(1) command),
		 * which will by definition not output anything until
		 * after it receives EOF. this means we can pipe both
		 * to its stdin and from its stdout, without risk of
		 * deadlock. it also means a full store-and-forward of
		 * the result, which increases latency to the first
		 * output for our user.
		 */
		int p1[2], p2[2];

		if (pipe(p1) < 0 || pipe(p2) < 0)
			my_panic(true, "pipe");
		if ((writer->sort_pid = fork()) < 0)
			my_panic(true, "fork");
		if (writer->sort_pid == 0)
			exec_sort(p1, p2);
		close(p1[0]);
		writer->sort_stdin = fdopen(p1[1], "w");
		writer->sort_stdout = fdopen(p2[0], "r");
		close(p2[1]);
	}

	writer->next = writers;
	writers = writer;
	return writer;
}

void
ps_stdout(writer_t writer) {
	fwrite(writer->ps_buf, 1, writer->ps_len, stdout);
}

/* query_status -- install a status code and description in a query.
 */
void
query_status(query_t query, const char *status, const char *message) {
	assert((query->status == NULL) == (query->message == NULL));
	if (query->multitype && query->status != NULL) {
		DESTROY(query->status);
		DESTROY(query->message);
	} else {
		assert(query->status == NULL);
	}
	query->status = strdup(status);
	query->message = strdup(message);
}

/* writer_func -- process a block of json text, from filesys or API socket.
 *
 * This function's signature must conform to write_callback() in
 * CURLOPT_WRITEFUNCTION.
 * Returns the number of bytes actually taken care of or returns
 * CURL_WRITEFUNC_PAUSE to pause this query's connection until
 * curl_easy_pause(..., CURLPAUSE_CONT) is called.
 */
size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	fetch_t fetch = (fetch_t) blob;
	query_t query = fetch->query;
	writer_t writer = query->writer;
	qparam_ct qp = &query->qp;
	size_t bytes = size * nmemb;
	char *nl;

	DEBUG(3, true, "writer_func(%d, %d): %d\n",
	      (int)size, (int)nmemb, (int)bytes);

	/* if we're in asynchronous batch mode, only one query can reach
	 * the writer at a time. fetches within a query can interleave. */
	if (batching == batch_verbose) {
		if (multiple) {
			if (writer->active == NULL) {
				/* grab the token. */
				writer->active = query;
				DEBUG(2, true, "active (%d) %s\n",
				      npaused, query->descr);
			} else if (writer->active != query) {
				/* pause the query. */
				paused[npaused++] = query;
				DEBUG(2, true, "pause (%d) %s\n",
				      npaused, query->descr);
				return CURL_WRITEFUNC_PAUSE;
			}
		}
		if (!query->hdr_sent) {
			printf("++ %s\n", query->descr);
			query->hdr_sent = true;
		}
	}

	fetch->buf = realloc(fetch->buf, fetch->len + bytes);
	memcpy(fetch->buf + fetch->len, ptr, bytes);
	fetch->len += bytes;

	/* when the fetch is a live web result, emit
	 * !2xx errors and info payloads as reports.
	 */
	if (fetch->easy != NULL) {
		if (fetch->rcode == 0)
			curl_easy_getinfo(fetch->easy,
					  CURLINFO_RESPONSE_CODE,
					  &fetch->rcode);
		if (fetch->rcode != HTTP_OK) {
			char *message = strndup(fetch->buf, fetch->len);

			/* only report the first line of data. */
			char *eol = strpbrk(message, "\r\n");
			if (eol != NULL)
				*eol = '\0';

			/* only remember the first response status. */
			if (query->status == NULL)
				query_status(query,
					     psys->status(fetch),
					     message);
			if (!quiet) {
				char *url;

				curl_easy_getinfo(fetch->easy,
						  CURLINFO_EFFECTIVE_URL,
						  &url);
				my_logf("warning: libcurl %ld [%s] %s",
					fetch->rcode, url, message);
			}
			DESTROY(message);
			fetch->buf[0] = '\0';
			fetch->len = 0;
			return bytes;
		}
	}

	/* deblock. */
	while ((nl = memchr(fetch->buf, '\n', fetch->len)) != NULL) {
		size_t pre_len = (size_t)(nl - fetch->buf),
			post_len = (fetch->len - pre_len) - 1;

		if (sorting == no_sort && writer->output_limit > 0 &&
		    writer->count >= writer->output_limit)
		{
			DEBUG(9, true, "hit output limit %ld\n",
			      qp->output_limit);
			/* cause CURLE_WRITE_ERROR for this transfer. */
			bytes = 0;
			if (psys->encap == encap_saf)
				fetch->saf_cond = sc_we_limited;
			/* inform io_engine() that the abort is intentional. */
			fetch->stopped = true;
		} else if (writer->meta_query) {
			/* concatenate this fragment (incl \n) to ps_buf. */
			writer->ps_buf = realloc(writer->ps_buf,
						 writer->ps_len + pre_len + 1);
			memcpy(writer->ps_buf + writer->ps_len,
			       fetch->buf, pre_len + 1);
			writer->ps_len += pre_len + 1;
		} else {
			query->writer->count += pdns_blob(fetch, pre_len);

			if (psys->encap == encap_saf)
				switch (fetch->saf_cond) {
				case sc_init:
				case sc_begin:
				case sc_ongoing:
				case sc_missing:
					break;
				case sc_succeeded:
				case sc_limited:
				case sc_failed:
				case sc_we_limited:
					/* inform io_engine() that the abort
					 * is intentional.
					 */
					fetch->stopped = true;
					break;
				}
		}
		memmove(fetch->buf, nl + 1, post_len);
		fetch->len = post_len;
	}

	return bytes;
}

/* last_fetch -- do something with leftover buffer data when a query ends.
 */
static void
last_fetch(fetch_t fetch) {
	query_t query = fetch->query;

	assert(query->fetches == fetch && fetch->next == NULL);
	DEBUG(2, true, "query_done(%s), meta=%d\n",
	      query->descr, query->writer->meta_query);
	if (query->writer->meta_query)
		return;

	if (batching == batch_none && !quiet) {
		const char *msg = or_else(fetch->saf_msg, "");

		if (fetch->saf_cond == sc_limited)
			my_logf("Database API limit: %s", msg);
		else if (fetch->saf_cond == sc_failed)
			my_logf("Database result: %s", msg);
		else if (fetch->saf_cond == sc_missing)
			my_logf("API response missing: %s", msg);
		else if (query->status != NULL && !query->multitype)
			my_logf("API status: %s (%s)",
				query->status, query->message);
	} else if (batching == batch_verbose) {
		/* if this was an actively written query, unpause another. */
		writer_t writer = query->writer;

		if (multiple) {
			assert(writer->active == query);
			writer->active = NULL;
		}
		assert(writer->ps_buf == NULL && writer->ps_len == 0);
		writer->ps_len = (size_t)
			asprintf(&writer->ps_buf, "-- %s (%s)\n",
				 or_else(query->status, status_noerror),
				 or_else(query->message,
					 or_else(fetch->saf_msg, "no error")));
		if (npaused > 0) {
			query_t unpause;
			fetch_t ufetch;
			int i;

			/* unpause the next query's fetches. */
			unpause = paused[0];
			npaused--;
			for (i = 0; i < npaused; i++)
				paused[i] = paused[i + 1];
			for (ufetch = unpause->fetches;
			     ufetch != NULL;
			     ufetch = ufetch->next) {
				DEBUG(2, true, "unpause (%d) %s\n",
				      npaused, unpause->descr);
				curl_easy_pause(ufetch->easy, CURLPAUSE_CONT);
			}
		}
	}
}

/* writer_fini -- stop a writer's fetches, and perhaps execute a POSIX "sort".
 */
void
writer_fini(writer_t writer) {
	/* unlink this writer from the global chain. */
	if (writers == writer) {
		writers = writer->next;
	} else {
		writer_t prev = NULL;
		writer_t temp;

		for (temp = writers; temp != NULL; temp = temp->next) {
			if (temp->next == writer) {
				prev = temp;
				break;
			}
		}
		assert(prev != NULL);
		prev->next = writer->next;
	}

	/* finish and close any fetches still cooking. */
	while (writer->queries != NULL) {
		query_t query = writer->queries,
			query_next = query->next;

		while (query->fetches != NULL) {
			fetch_t fetch = query->fetches,
				fetch_next = fetch->next;

			/* release any buffered info. */
			DESTROY(fetch->buf);
			if (fetch->len != 0) {
				my_logf("warning: stranding %d octets!",
					(int)fetch->len);
				fetch->len = 0;
			}

			/* release any fetch-specific data. */
			DESTROY(fetch->saf_msg);

			/* tear down any curl infrastructure on the fetch. */
			fetch_reap(fetch);
			fetch = NULL;
			query->fetches = fetch_next;
		}
		assert((query->status != NULL) == (query->message != NULL));
		DESTROY(query->status);
		DESTROY(query->message);
		DESTROY(query->descr);
		DESTROY(query);
		writer->queries = query_next;
	}

	/* drain the sort if there is one. */
	if (writer->sort_pid != 0) {
		int status, count;
		char *line = NULL;
		size_t n = 0;

		/* when sorting, there has been no output yet. gather the
		 * intermediate representation from the POSIX sort stdout,
		 * skip over the sort keys we added earlier, and process.
		 */
		fclose(writer->sort_stdin);
		DEBUG(1, true, "closed sort_stdin, wrote %d objs\n",
			 writer->count);
		count = 0;
		while (getline(&line, &n, writer->sort_stdout) > 0) {
			/* if we're above the limit, ignore remaining output.
			 * this is nec'y to avoid SIGPIPE from sort if we were
			 * to close its stdout pipe without emptying it first.
			 */
			if (writer->output_limit > 0 &&
			    count >= writer->output_limit)
			{
				if (!writer->sort_killed) {
					kill(writer->sort_pid, SIGTERM);
					writer->sort_killed = true;
				}
				continue;
			}

			struct pdns_tuple tup;
			char *nl, *linep;
			const char *msg;
			size_t len;

			if ((nl = strchr(line, '\n')) == NULL) {
				my_logf("warning: no \\n found in '%s'", line);
				continue;
			}
			linep = line;
			DEBUG(2, true, "sort1: '%*.*s'\n",
				 (int)(nl - linep),
				 (int)(nl - linep),
				 linep);
			/* skip sort key: first */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no SP found in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: last */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no second SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: duration */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no third SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: count */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no fourth SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: rrname */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no fifth SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: rrtype */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no sixth SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* skip sort key: rdata */
			if ((linep = strchr(linep, ' ')) == NULL) {
				my_logf("warning: no seventh SP in '%s'", line);
				continue;
			}
			linep += strspn(linep, " ");
			/* recover the json */
			DEBUG(2, true, "sort2: '%*.*s'\n",
				 (int)(nl - linep),
				 (int)(nl - linep),
				 linep);
			len = (size_t)(nl - linep);
			msg = tuple_make(&tup, linep, len);
			if (msg != NULL) {
				my_logf("warning: tuple_make: %s", msg);
				continue;
			}
			/* after the sort, we don't know what query
			 * caused any given tuple.
			 */
			(*presenter->output)(&tup, NULL, writer);
			tuple_unmake(&tup);
			count++;
		}
		DESTROY(line);
		fclose(writer->sort_stdout);
		DEBUG(1, true, "closed sort_stdout, read %d objs (lim %ld)\n",
		      count, writer->output_limit);
		if (waitpid(writer->sort_pid, &status, 0) < 0) {
			perror("waitpid");
		} else {
			if (!writer->sort_killed && status != 0)
				my_logf("warning: sort exit status is %u",
					(unsigned)status);
		}
	}

	/* burp out the stored postscript, if any, and destroy it. */
	if (writer->ps_len > 0) {
		assert(writer->ps_user != NULL);
		writer->ps_user(writer);
		DESTROY(writer->ps_buf);
		writer->ps_len = 0;
	}

	DESTROY(writer);
}

void
unmake_writers(void) {
	while (writers != NULL)
		writer_fini(writers);
}

/* io_engine -- let libcurl run until there are few enough outstanding jobs.
 */
void
io_engine(int jobs) {
	int still, repeats, numfds;

	DEBUG(2, true, "io_engine(%d)\n", jobs);

	/* let libcurl run while there are too many jobs remaining. */
	still = 0;
	repeats = 0;
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > jobs) {
		DEBUG(3, true, "...waiting (still %d)\n", still);
		numfds = 0;
		if (curl_multi_wait(multi, NULL, 0, 0, &numfds) != CURLM_OK)
			break;
		if (numfds == 0) {
			/* curl_multi_wait() can return 0 fds for no reason. */
			if (++repeats > 1) {
				struct timespec req, rem;

				req = (struct timespec){
					.tv_sec = 0,
					.tv_nsec = 100*1000*1000  // 100ms
				};
				while (nanosleep(&req, &rem) == EINTR) {
					/* as required by nanosleep(3). */
					req = rem;
				}
			}
		} else {
			repeats = 0;
		}
		io_drain();
	}
	io_drain();
}

/* io_drain -- drain the response code reports.
 */
static void
io_drain(void) {
	struct CURLMsg *cm;
	int still = 0;

	while ((cm = curl_multi_info_read(multi, &still)) != NULL) {
		fetch_t fetch;
		query_t query;
		char *private;

		curl_easy_getinfo(cm->easy_handle,
				  CURLINFO_PRIVATE,
				  &private);
		fetch = (fetch_t) private;
		query = fetch->query;

		if (cm->msg == CURLMSG_DONE) {
			if (fetch->rcode == 0)
				curl_easy_getinfo(fetch->easy,
						  CURLINFO_RESPONSE_CODE,
						  &fetch->rcode);

			DEBUG(2, true, "io_drain(%s) DONE rcode=%d\n",
			      query->descr, fetch->rcode);
			if (psys->encap == encap_saf) {
				if (fetch->saf_cond == sc_begin ||
				    fetch->saf_cond == sc_ongoing)
				{
					/* stream ended without a terminating
					 * SAF value, so override stale value
					 * we received before the problem.
					 */
					fetch->saf_cond = sc_missing;
					fetch->saf_msg = strdup(
						"Data transfer failed "
						"-- No SAF terminator "
						"at end of stream");
					query_status(query,
						     status_error,
						     fetch->saf_msg);
				}
				DEBUG(2, true, "... saf_cond %d saf_msg %s\n",
				      fetch->saf_cond,
				      or_else(fetch->saf_msg, ""));
			}
			if (cm->data.result == CURLE_COULDNT_RESOLVE_HOST) {
				my_logf("libcurl failed since "
					"could not resolve host");
				exit_code = 1;
			} else if (cm->data.result == CURLE_COULDNT_CONNECT) {
				my_logf("libcurl failed since "
					"could not connect");
				exit_code = 1;
			} else if (cm->data.result != CURLE_OK &&
				   !fetch->stopped)
			{
				my_logf("libcurl failed with "
					"curl error %d (%s)",
					cm->data.result,
					curl_easy_strerror(cm->data.result));
				exit_code = 1;
			}

			/* record emptiness as status if nothing else. */
			if (psys->encap == encap_saf &&
			    query->writer != NULL &&
			    !query->writer->meta_query &&
			    query->writer->count == 0 &&
			    query->status == NULL)
			{
				query_status(query,
					     status_noerror,
					     "no results found for query.");
			}

			fetch_done(fetch);
			fetch_unlink(fetch);
			fetch_reap(fetch);
		}
		DEBUG(3, true, "...info read (still %d)\n", still);
	}
}

/* escape -- HTML-encode a string, returns a string which must be free()'d.
 */
char *
escape(const char *str) {
	char *escaped, *ret;

	if (str == NULL)
		return NULL;
	escaped = curl_escape(str, (int)strlen(str));
	if (escaped == NULL) {
		my_logf("curl_escape(%s) failed", str);
		my_exit(1);
	}
	ret = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
	return ret;
}
