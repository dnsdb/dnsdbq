CURLINCL = `curl-config --cflags` 
JANSINCL = -I/usr/local/include

CURLLIBS = `[ ! -z "$$(curl-config --libs)" ] && curl-config --libs || curl-config --static-libs`
JANSLIBS = -L/usr/local/lib -ljansson

CWARN =-W -Wall -Wextra -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
# try shipping without any warnings
CWARN   +=-Werror

CDEBUG = -g
CFLAGS += $(CDEBUG) $(CWARN)
DNSDB_QUERY_OBJ = dnsdb_query.o ns_ttl.o

all: dnsdb_query

clean:
	rm -f dnsdb_query
	rm -f $(DNSDB_QUERY_OBJ)

dnsdb_query: $(DNSDB_QUERY_OBJ) Makefile
	$(CC) -o dnsdb_query $(DNSDB_QUERY_OBJ) $(CURLLIBS) $(JANSLIBS)

.c.o:
	$(CC) $(CFLAGS) $(CURLINCL) $(JANSINCL) -c $<
