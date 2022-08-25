CC=gcc
COMMONFLAGS=-g -Wall -lpthread
CFLAGS=$(COMMONFLAGS) -O0 -DDEBUG

PROJNAME=nanofuzz

SRC=src
SRCS=$(wildcard $(SRC)/*.c)

OBJ=obj
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

BINDIR=bin
BIN=$(BINDIR)/$(PROJNAME)

LIB=lib
SLIBOUT=$(LIB)/lib$(PROJNAME).a
DLIBOUT=$(LIB)/lib$(PROJNAME).so

TEST=tests
TESTS=$(wildcard $(TEST)/*.c)
TESTOBJ=$(TEST)/obj
TESTBIN=$(TEST)/bin
TESTOBJS=$(patsubst $(TEST)/%.c, $(TESTOBJ)/%.o, $(TESTS))
TESTBINS=$(patsubst $(TEST)/%.c, $(TESTBIN)/%, $(TESTS))
TEST_COMPLIANCE=$(TEST)/compliance.py
TEST_ITERS=50


# By default, don't run tests. Just build the application.
all: $(BIN)


# Static library file for testing. Excludes the main.o object.
slib: $(SLIBOUT)

$(LIB):
	-mkdir $(LIB)

$(SLIBOUT): $(LIB) $(OBJ) $(OBJS)
	ar rcs $(SLIBOUT) $$(echo -n "$(OBJS)" | sed 's/$(OBJ)\/main.o//')


# Release build is intended the be 'optimized' and tested thoroughly.
release: clean
release: EXTFLAGS=-O3 -DNDEBUG
release: TEST_ITERS=100
release: tests


# Clean structures.
clean:
	-rm -r $(BINDIR) $(OBJ)
	-rm -r $(TESTBIN) $(TESTOBJ)
	-rm -r $(LIB)


# Create the actual CLI executable.
$(OBJ):
	-mkdir $(OBJ)

$(BINDIR):
	-mkdir $(BINDIR)

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ) $(BINDIR) $(OBJS)
	-rm $(BIN)
	$(CC) $(CFLAGS) $(OBJS) -o $@


# TEST CASES. Creates the necessary folder structure for Criterion tests, and run them.
.PHONY: tests
tests: CFLAGS=-L./lib/ -L/usr/local/lib64 -Wl,-rpath,/usr/local/lib64 $(COMMONFLAGS) $(EXTFLAGS)
tests: all slib $(TESTOBJ) $(TESTBIN) $(TESTBINS)
	for x in $(TESTBINS) ; do ./$$x ; done
	if [ ! -x $(TEST_COMPLIANCE) ]; then chmod +x $(TEST_COMPLIANCE); fi
	$(TEST_COMPLIANCE) $(TEST_ITERS)

$(TESTOBJ):
	-mkdir $(TESTOBJ)

$(TESTBIN):
	-mkdir $(TESTBIN)

$(TESTOBJ)/%.o: $(TEST)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBIN)/%: $(TESTOBJS)
	$(CC) $(CFLAGS) $(TESTOBJS) -o $@ -l$(PROJNAME) -lcriterion
