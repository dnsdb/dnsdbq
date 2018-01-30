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

TOOL = dnsdbq
TOOL_OBJ = $(TOOL).o ns_ttl.o

all: $(TOOL)

install: all
	rm -f /usr/local/bin/$(TOOL)
	cp $(TOOL) /usr/local/bin/$(TOOL)
	rm -f /usr/local/share/man/man1/$(TOOL).1
	cp $(TOOL).man /usr/local/share/man/man1/$(TOOL).1

clean:
	rm -f $(TOOL)
	rm -f $(TOOL_OBJ)

dnsdbq: $(TOOL_OBJ) Makefile
	$(CC) -o $(TOOL) $(TOOL_OBJ) $(CURLLIBS) $(JANSLIBS)

.c.o:
	$(CC) $(CFLAGS) $(CURLINCL) $(JANSINCL) -c $<
