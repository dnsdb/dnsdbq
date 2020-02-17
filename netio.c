/* make_curl -- perform global initializations of libcurl.
 */
void
make_curl(void) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_cleanup_needed++;
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
		curl_cleanup_needed = 0;
	}
}

/* reader_launch -- given a url, tell libcurl to go fetch it.
 */
void
reader_launch(writer_t writer, char *url) {
	reader_t reader = NULL;
	CURLMcode res;

	DEBUG(2, true, "reader_launch(%s)\n", url);
	CREATE(reader, sizeof *reader);
	reader->writer = writer;
	writer = NULL;
	reader->easy = curl_easy_init();
	if (reader->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		DESTROY(reader);
		DESTROY(url);
		my_exit(1);
	}
	reader->url = url;
	url = NULL;
	curl_easy_setopt(reader->easy, CURLOPT_URL, reader->url);
	if (donotverify) {
		curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(reader->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	sys->auth(reader);
	reader->hdrs = curl_slist_append(reader->hdrs, json_header);
	curl_easy_setopt(reader->easy, CURLOPT_HTTPHEADER, reader->hdrs);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(reader->easy, CURLOPT_WRITEDATA, reader);
#if CURL_AT_LEAST_VERSION(7,42,0)
	/* do not allow curl to swallow /./ and /../ in our URLs */
	curl_easy_setopt(reader->easy, CURLOPT_PATH_AS_IS, 1L);
#endif /* CURL_AT_LEAST_VERSION */
	if (debug_level >= 3)
		curl_easy_setopt(reader->easy, CURLOPT_VERBOSE, 1L);

	/* linked-list insert. */
	reader->next = reader->writer->readers;
	reader->writer->readers = reader;

	res = curl_multi_add_handle(multi, reader->writer->readers->easy);
	if (res != CURLM_OK) {
		fprintf(stderr, "%s: curl_multi_add_handle() failed: %s\n",
			program_name, curl_multi_strerror(res));
		my_exit(1);
	}
}

/* reader_reap -- reap one reader.
 */
void
reader_reap(reader_t reader) {
	if (reader->easy != NULL) {
		curl_multi_remove_handle(multi, reader->easy);
		curl_easy_cleanup(reader->easy);
		reader->easy = NULL;
	}
	if (reader->hdrs != NULL) {
		curl_slist_free_all(reader->hdrs);
		reader->hdrs = NULL;
	}
	DESTROY(reader->url);
	DESTROY(reader);
}

/* writer_init -- instantiate a writer, which may involve forking a "sort".
 */
static writer_t
writer_init(u_long after, u_long before) {
	writer_t writer = NULL;

	CREATE(writer, sizeof(struct writer));

	if (sorted != no_sort) {
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

	writer->after = after;
	writer->before = before;
	writer->next = writers;
	writers = writer;
	return (writer);
}

/* writer_status -- install a status code and description in a writer.
 */
static void
writer_status(writer_t writer, const char *status, const char *message) {
	assert((writer->status == NULL) == (writer->message == NULL));
	assert(writer->status == NULL);
	writer->status = strdup(status);
	writer->message = strdup(message);
}

/* writer_func -- process a block of json text, from filesys or API socket.
 */
static size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	reader_t reader = (reader_t) blob;
	size_t bytes = size * nmemb;
	u_long after, before;
	FILE *outf;
	char *nl;

	DEBUG(3, true, "writer_func(%d, %d): %d\n",
	      (int)size, (int)nmemb, (int)bytes);

	reader->buf = realloc(reader->buf, reader->len + bytes);
	memcpy(reader->buf + reader->len, ptr, bytes);
	reader->len += bytes;

	/* when the reader is a live web result, emit
	 * !2xx errors and info payloads as reports.
	 */
	if (reader->easy != NULL) {
		if (reader->rcode == 0)
			curl_easy_getinfo(reader->easy,
					  CURLINFO_RESPONSE_CODE,
					  &reader->rcode);
		if (reader->rcode != 200) {
			char *message = strndup(reader->buf, reader->len);
			char *newline = strchr(message, '\n');
			if (newline != NULL)
				*newline = '\0';

			if (!reader->writer->once) {
				writer_status(reader->writer,
					      sys->status(reader),
					      message);
				if (!quiet) {
					char *url;
					
					curl_easy_getinfo(reader->easy,
							 CURLINFO_EFFECTIVE_URL,
							  &url);
					fprintf(stderr,
						"%s: warning: "
						"libcurl %ld [%s]\n",
						program_name, reader->rcode,
						url);
				}
				reader->writer->once = true;
			}
			if (!quiet)
				fprintf(stderr, "%s: warning: libcurl: [%s]\n",
					program_name, message);
			DESTROY(message);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}
	}

	after = reader->writer->after;
	before = reader->writer->before;
	outf = (sorted != no_sort) ? reader->writer->sort_stdin : stdout;

	while ((nl = memchr(reader->buf, '\n', reader->len)) != NULL) {
		size_t pre_len, post_len;

		if (info) {
			sys->write_info(reader);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}

		if (sorted == no_sort && output_limit != -1 &&
		    reader->writer->count >= output_limit)
		{
			DEBUG(1, true, "hit output limit %ld\n", output_limit);
			reader->buf[0] = '\0';
			reader->len = 0;
			return (bytes);
		}

		pre_len = (size_t)(nl - reader->buf);
		reader->writer->count += input_blob(reader->buf, pre_len,
						    after, before, outf);
		post_len = (reader->len - pre_len) - 1;
		memmove(reader->buf, nl + 1, post_len);
		reader->len = post_len;
	}
	return (bytes);
}

/* writer_fini -- stop a writer's readers, and perhaps execute a POSIX "sort".
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

	/* finish and close any readers still cooking. */
	while (writer->readers != NULL) {
		reader_t reader = writer->readers;

		/* release any buffered info. */
		DESTROY(reader->buf);
		if (reader->len != 0) {
			fprintf(stderr, "%s: warning: stranding %d octets!\n",
				program_name, (int)reader->len);
			reader->len = 0;
		}

		/* tear down any curl infrastructure on the reader & remove. */
		reader_t next = reader->next;
		reader_reap(reader);
		reader = NULL;
		writer->readers = next;
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
			if (output_limit != -1 && count >= output_limit) {
				if (!writer->sort_killed) {
					kill(writer->sort_pid, SIGTERM);
					writer->sort_killed = true;
				}
				continue;
			}

			char *nl, *linep;
			const char *msg;
			struct pdns_tuple tup;

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
			msg = tuple_make(&tup, linep, (size_t)(nl - linep));
			if (msg != NULL) {
				fprintf(stderr,
					"%s: warning: tuple_make: %s\n",
					program_name, msg);
				continue;
			}
			(*pres)(&tup, linep, (size_t)(nl - linep), stdout);
			tuple_unmake(&tup);
			count++;
		}
		DESTROY(line);
		fclose(writer->sort_stdout);
		DEBUG(1, true, "closed sort_stdout, read %d objs (lim %ld)\n",
		      count, query_limit);
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

	/* drop message and status strings if present. */
	assert((writer->status != NULL) == (writer->message != NULL));
	if (writer->status != NULL)
		DESTROY(writer->status);
	if (writer->message != NULL)
		DESTROY(writer->message);

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
	struct CURLMsg *cm;

	DEBUG(2, true, "io_engine(%d)\n", jobs);

	/* let libcurl run while there are too many jobs remaining. */
	still = 0;
	repeats = 0;
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > jobs) {
		DEBUG(4, true, "...waiting (still %d)\n", still);
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
	}

	/* drain the response code reports. */
	still = 0;
	while ((cm = curl_multi_info_read(multi, &still)) != NULL) {
		if (cm->msg == CURLMSG_DONE && cm->data.result != CURLE_OK) {
			if (cm->data.result == CURLE_COULDNT_RESOLVE_HOST)
				fprintf(stderr,
					"%s: warning: libcurl failed since "
					"could not resolve host\n",
					program_name);
			else if (cm->data.result == CURLE_COULDNT_CONNECT)
				fprintf(stderr,
					"%s: warning: libcurl failed since "
					"could not connect\n",
					program_name);
			else
				fprintf(stderr,
					"%s: warning: libcurl failed with "
					"curl error %d\n",
					program_name, cm->data.result);
			exit_code = 1;
		}
		DEBUG(4, true, "...info read (still %d)\n", still);
	}
}

