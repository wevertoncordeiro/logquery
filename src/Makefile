########################################################################
# Code listing from "Advanced Linux Programming," by CodeSourcery LLC  #
# Copyright (C) 2001 by New Riders Publishing                          #
# See COPYRIGHT for license information.                               #
########################################################################

### Configuration.  ####################################################

# C source files for the server.
SOURCES		= conf.c server.c common.c main.c nat.c module.c
# C Flags
CFLAGS          = -O2 -pedantic -W -Wall -DDAEMON_MODE
# Object files corresponding to source files.
OBJECTS		= $(SOURCES:.c=.o)
# Server module shared library files.
MODULES         = dns.so firewall.so

### Rules.  ############################################################

.PHONY:         all clean

# Default target: build everything.
all:            logquery $(MODULES)

# Clean up build products.
clean:
	rm -f *~ $(OBJECTS) $(MODULES) logquery 

# The main server program.  Link with -Wl,-export-dyanamic so
# dynamically loaded modules can bind symbols in the program.  Link in
# libdl, which contains calls for dynamic loading.
logquery:         $(OBJECTS)
	$(CC) $(CFLAGS) -Wl,-export-dynamic -o $@ $^ -lxml2 -lz -ldl

# All object files in the server depend on server.h.  But use the
# default rule for building object files from source files.
$(OBJECTS):     server.h

# Rule for building module shared libraries from the corresponding
# source files.   Compile -fPIC and generate a shared object file.
$(MODULES): \
%.so:           %.c server.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -lxml2 -lz

