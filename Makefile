CC=gcc
COMMONFLAGS=-g -Wall
CFLAGS=$(COMMONFLAGS) -DDEBUG

SRC=src
SRCS=$(wildcard $(SRC)/*.c)

OBJ=obj
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

BINDIR=bin
BIN=$(BINDIR)/nanofuzz

TEST=tests
TESTS=$(wildcard $(TEST)/*.c)
TESTOBJS=$(patsubst $(TEST)/%.c, $(TEST)/obj/%.o, $(TESTS))
TESTBINS=$(patsubst $(TEST)/%.c, $(TEST)/bin/%, $(TESTS))


# By default, don't run tests. Just build the application.
all: $(BIN)


# Release build is intended the be 'optimized' and tested thoroughly.
release: CFLAGS=$(COMMONFLAGS) -O3 -DNDEBUG
release: clean
release: tests


# Clean structure.
clean:
	-rm -r $(BINDIR)/* $(OBJ)/*
	-rm -r $(TEST)/bin $(TEST)/obj


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
tests:CFLAGS=-L/usr/local/lib64 -Wl,-rpath,/usr/local/lib64 $(COMMONFLAGS)
tests: all $(TEST)/obj $(TEST)/bin $(TESTBINS)
	for x in $(TESTBINS) ; do ./$$x ; done

$(TEST)/obj:
	-mkdir $(TEST)/obj

$(TEST)/bin:
	-mkdir $(TEST)/bin

$(TEST)/obj/%.o: $(TEST)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST)/bin/%: $(TESTOBJS)
	$(CC) $(CFLAGS) $(TESTOBJS) -o $@ -lcriterion
