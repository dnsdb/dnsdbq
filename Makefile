CURLINCL = `curl-config --cflags` 
JANSINCL = -I/usr/local/include

CURLLIBS = `[ ! -z $$(curl-config --libs) ] && curl-config --libs || curl-config --static-libs`
JANSLIBS = -L/usr/local/lib -ljansson

CWARN =-W -Wall -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
# -Wunreachable-code is often wrong
#CWARN  +=-Wunreachable-code
# try shipping without any warnings
CWARN   +=-Werror

CDEBUG = -g
CFLAGS += $(CDEBUG) $(CWARN)

all: dnsdb_query

clean:
	rm -f dnsdb_query
	rm -f *.o

dnsdb_query: dnsdb_query.o Makefile
	cc -o dnsdb_query dnsdb_query.o $(CURLLIBS) $(JANSLIBS)

.c.o:
	cc $(CFLAGS) $(CURLINCL) $(JANSINCL) -c $<
