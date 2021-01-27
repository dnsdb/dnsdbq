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

CDEFS = -DWANT_PDNS_DNSDB=1 -DWANT_PDNS_DNSDB2=1 -DWANT_PDNS_CIRCL=1
CGPROF =
CDEBUG = -g -O3
CFLAGS += $(CGPROF) $(CDEBUG) $(CWARN) $(CDEFS)
INCL= $(CURLINCL) $(JANSINCL)
LIBS= $(CURLLIBS) $(JANSLIBS) -lresolv

TOOL = dnsdbq
TOOL_OBJ = $(TOOL).o ns_ttl.o netio.o \
	pdns.o pdns_circl.o pdns_dnsdb.o pdns_asn.o \
	sort.o time.o
TOOL_SRC = $(TOOL).c ns_ttl.c netio.c \
	pdns.c pdns_circl.c pdns_dnsdb.c pdns_asn.c \
	sort.c time.c

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
	$(CC) $(CDEBUG) -o $(TOOL) $(CGPROF) $(TOOL_OBJ) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCL) -c $<

$(TOOL_OBJ): Makefile

# BSD only
depend:
	mkdep $(CURLINCL) $(JANSINCL) $(CDEFS) $(TOOL_SRC)

# these were made by mkdep on BSD but are now staticly edited
dnsdbq.o: dnsdbq.c \
  defs.h netio.h \
  pdns.h \
  pdns_dnsdb.h pdns_circl.h sort.h \
  time.h globals.h
ns_ttl.o: ns_ttl.c \
  ns_ttl.h
netio.o: netio.c \
  defs.h netio.h \
  pdns.h \
  globals.h sort.h
pdns.o: pdns.c defs.h \
  netio.h \
  pdns.h \
  time.h \
  globals.h sort.h
pdns_circl.o: pdns_circl.c \
  defs.h \
  pdns.h \
  netio.h \
  pdns_circl.h globals.h sort.h
pdns_dnsdb.o: pdns_dnsdb.c \
  defs.h \
  pdns.h \
  netio.h \
  pdns_dnsdb.h time.h globals.h sort.h
sort.o: sort.c \
  defs.h sort.h pdns.h \
  netio.h \
  globals.h
time.o: time.c \
  defs.h time.h \
  globals.h sort.h pdns.h \
  netio.h \
  ns_ttl.h
