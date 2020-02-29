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

static void io_drain(void);
static void fetch_reap(fetch_t);
static void fetch_done(fetch_t);
static void fetch_unlink(fetch_t);
static void query_done(query_t);

static writer_t writers = NULL;
static CURLM *multi = NULL;
static bool curl_cleanup_needed = false;
static query_t paused[MAX_JOBS];
static int npaused = 0;

/* make_curl -- perform global initializations of libcurl.
 */
void
make_curl(void) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_cleanup_needed = true;
	multi = curl_multi_init();
	if (multi == NULL) {
		fprintf(stderr, "%s: curl_multi_init() failed\n",
			program_name);
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

/* fetch -- given a url, tell libcurl to go fetch it.
 */
void
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
	psys->auth(fetch);
	fetch->hdrs = curl_slist_append(fetch->hdrs, json_header);
	curl_easy_setopt(fetch->easy, CURLOPT_HTTPHEADER, fetch->hdrs);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEDATA, fetch);
	curl_easy_setopt(fetch->easy, CURLOPT_PRIVATE, fetch);
#if CURL_AT_LEAST_VERSION(7,42,0)
	/* do not allow curl to swallow /./ and /../ in our URLs */
	curl_easy_setopt(fetch->easy, CURLOPT_PATH_AS_IS, 1L);
#endif /* CURL_AT_LEAST_VERSION */
	if (debug_level >= 3)
		curl_easy_setopt(fetch->easy, CURLOPT_VERBOSE, 1L);

	/* linked-list insert. */
	fetch->next = fetch->query->fetches;
	fetch->query->fetches = fetch;

	res = curl_multi_add_handle(multi, fetch->easy);
	if (res != CURLM_OK) {
		fprintf(stderr, "%s: curl_multi_add_handle() failed: %s\n",
			program_name, curl_multi_strerror(res));
		my_exit(1);
	}
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
		query_done(query);
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
writer_init(long output_limit) {
	writer_t writer = NULL;

	CREATE(writer, sizeof(struct writer));
	writer->output_limit = output_limit;

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
	return (writer);
}

/* query_status -- install a status code and description in a query.
 */
void
query_status(query_t query, const char *status, const char *message) {
	assert((query->status == NULL) == (query->message == NULL));
	assert(query->status == NULL);
	query->status = strdup(status);
	query->message = strdup(message);
}

/* writer_func -- process a block of json text, from filesys or API socket.
 */
size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	fetch_t fetch = (fetch_t) blob;
	query_t query = fetch->query;
	writer_t writer = query->writer;
	qparam_ct qp = &query->params;
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
				      npaused, query->command);
			} else if (writer->active != query) {
				/* pause the query. */
				paused[npaused++] = query;
				DEBUG(2, true, "pause (%d) %s\n",
				      npaused, query->command);
				return CURL_WRITEFUNC_PAUSE;
			}
		}
		if (!query->h_sent) {
			if (batching == batch_verbose)
				printf("++ %s\n", query->command);
			query->h_sent = true;
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
		if (fetch->rcode != 200) {
			char *message = strndup(fetch->buf, fetch->len);
			char *eol = strpbrk(message, "\r\n");
			if (eol != NULL)
				*eol = '\0';

			if (!query->e_sent) {
				query_status(query,
					     psys->status(fetch),
					     message);
				if (!quiet) {
					char *url;
					
					curl_easy_getinfo(fetch->easy,
							CURLINFO_EFFECTIVE_URL,
							  &url);
					fprintf(stderr,
						"%s: warning: "
						"libcurl %ld [%s]\n",
						program_name, fetch->rcode,
						url);
				}
				query->e_sent = true;
			}
			if (!quiet)
				fprintf(stderr, "%s: warning: libcurl: [%s]\n",
					program_name, message);
			DESTROY(message);
			fetch->buf[0] = '\0';
			fetch->len = 0;
			return (bytes);
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
			/* inform io_engine() that the abort is intentional. */
			fetch->stopped = true;
		} else if (query->info) {
			/* concatenate this fragment (with \n) to info_buf. */
			char *temp = NULL;

			asprintf(&temp, "%s%*.*s\n",
				 or_else(query->info_buf, ""),
				 (int)pre_len, (int)pre_len, fetch->buf);
			DESTROY(query->info_buf);
			query->info_buf = temp;
			query->info_len += pre_len + 1;
		} else {
			query->writer->count +=
				data_blob(query,
					  fetch->buf,
					  pre_len);
		}
		memmove(fetch->buf, nl + 1, post_len);
		fetch->len = post_len;
	}

	return (bytes);
}

/* query_done -- do something with leftover buffer data when a query ends.
 */
static void
query_done(query_t query) {
	DEBUG(2, true, "query_done(%s)\n", query->command);

	/* burp out the stored info blob, if any, and destroy it. */
	if (query->info) {
		if (query->info_len > 0) {
			psys->info_blob(query->info_buf, query->info_len);
			DESTROY(query->info_buf);
			query->info_len = 0;
		}
	}

	/* if this was an actively written query, unpause another. */
	if (batching == batch_verbose) {
		writer_t writer = query->writer;

		if (multiple) {
			assert(writer->active == query);
			writer->active = NULL;
		}
		printf("-- %s (%s)\n",
			or_else(query->status, "NOERROR"),
			or_else(query->message, "no error"));
		if (npaused > 0) {
			query_t unpause;
			fetch_t fetch;
			int i;

			unpause = paused[0];
			npaused--;
			for (i = 0; i < npaused; i++)
				paused[i] = paused[i + 1];
			for (fetch = unpause->fetches;
			     fetch != NULL;
			     fetch = fetch->next) {
				DEBUG(2, true, "unpause (%d) %s\n",
				      npaused, unpause->command);
				curl_easy_pause(fetch->easy, CURLPAUSE_CONT);
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
				fprintf(stderr,
					"%s: warning: stranding %d octets!\n",
					program_name, (int)fetch->len);
				fetch->len = 0;
			}

			/* tear down any curl infrastructure on the fetch. */
			fetch_reap(fetch);
			fetch = NULL;
			query->fetches = fetch_next;
		}
		assert((query->status != NULL) == (query->message != NULL));
		DESTROY(query->status);
		DESTROY(query->message);
		DESTROY(query->command);
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
				fprintf(stderr,
					"%s: warning: no \\n found in '%s'\n",
					program_name, line);
				continue;
			}
			linep = line;
			DEBUG(2, true, "sort1: '%*.*s'\n",
				 (int)(nl - linep),
				 (int)(nl - linep),
				 linep);
			/* skip sort keys (first, last, count, name, data). */
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"%s: warning: no SP found in '%s'\n",
					program_name, line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"%s: warning: no second SP in '%s'\n",
					program_name, line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"%s: warning: no third SP in '%s'\n",
					program_name, line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"%s: warning: no fourth SP in '%s'\n",
					program_name, line);
				continue;
			}
			linep += strspn(linep, " ");
			if ((linep = strchr(linep, ' ')) == NULL) {
				fprintf(stderr,
					"%s: warning: no fifth SP in '%s'\n",
					program_name, line);
				continue;
			}
			linep += strspn(linep, " ");
			DEBUG(2, true, "sort2: '%*.*s'\n",
				 (int)(nl - linep),
				 (int)(nl - linep),
				 linep);
			len = (size_t)(nl - linep);
			msg = tuple_make(&tup, linep, len);
			if (msg != NULL) {
				fprintf(stderr,
					"%s: warning: tuple_make: %s\n",
					program_name, msg);
				continue;
			}
			(*presenter)(&tup, linep, len, stdout);
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
				fprintf(stderr,
					"%s: warning: sort "
					"exit status is %u\n",
					program_name, (unsigned)status);
		}
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
			DEBUG(2, true, "io_engine(%s) DONE\n", query->command);
			if (cm->data.result == CURLE_COULDNT_RESOLVE_HOST) {
				fprintf(stderr,
					"%s: warning: libcurl failed since "
					"could not resolve host\n",
					program_name);
				exit_code = 1;
			} else if (cm->data.result == CURLE_COULDNT_CONNECT) {
				fprintf(stderr,
					"%s: warning: libcurl failed since "
					"could not connect\n",
					program_name);
				exit_code = 1;
			} else if (cm->data.result != CURLE_OK &&
				   !fetch->stopped)
			{
				fprintf(stderr,
					"%s: warning: libcurl failed with "
					"curl error %d (%s)\n",
					program_name, cm->data.result,
					curl_easy_strerror(cm->data.result));
				exit_code = 1;
			}
			fetch_done(fetch);
			fetch_unlink(fetch);
			fetch_reap(fetch);
		}
		DEBUG(3, true, "...info read (still %d)\n", still);
	}
}

/* escape -- HTML-encode a string, in place.
 */
void
escape(CURL *easy, char **str) {
	char *escaped;

	if (*str == NULL)
		return;
	escaped = curl_easy_escape(easy, *str, (int)strlen(*str));
	if (escaped == NULL) {
		fprintf(stderr, "%s: curl_escape(%s) failed\n",
			program_name, *str);
		my_exit(1);
	}
	DESTROY(*str);
	*str = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
}
