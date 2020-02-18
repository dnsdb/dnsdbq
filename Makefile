#
# Copyright (c) 2014-2020 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CURLINCL = `curl-config --cflags` 
JANSINCL = -I/usr/local/include

CURLLIBS = `[ ! -z "$$(curl-config --libs)" ] && curl-config --libs || curl-config --static-libs`
JANSLIBS = -L/usr/local/lib -ljansson

CWARN =-W -Wall -Wextra -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wconversion
# try shipping without any warnings
CWARN   +=-Werror
# warning about bad indentation, only for clang 6.x+
#CWARN   +=-Werror=misleading-indentation

CDEFS = -DWANT_PDNS_CIRCL=1
CGPROF =
CDEBUG = -g
CFLAGS += $(CGPROF) $(CDEBUG) $(CWARN) $(CDEFS)

TOOL = dnsdbq
TOOL_OBJ = $(TOOL).o ns_ttl.o netio.o pdns.o pdns_circl.o pdns_dnsdb.o \
	sort.o time.o

all: $(TOOL)

install: all
	rm -f /usr/local/bin/$(TOOL)
	mkdir -p /usr/local/bin
	cp $(TOOL) /usr/local/bin/$(TOOL)
	rm -f /usr/local/share/man/man1/$(TOOL).1
	mkdir -p /usr/local/share/man/man1
	cp $(TOOL).man /usr/local/share/man/man1/$(TOOL).1

clean:
	rm -f $(TOOL)
	rm -f $(TOOL_OBJ)

dnsdbq: $(TOOL_OBJ) Makefile
	$(CC) $(CDEBUG) -o $(TOOL) $(CGPROF) $(TOOL_OBJ) $(CURLLIBS) $(JANSLIBS)

.c.o:
	$(CC) $(CFLAGS) $(CURLINCL) $(JANSINCL) -c $<

time.o: ns_ttl.h
