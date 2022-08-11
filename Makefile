CC=gcc
COMMONFLAGS=-g -Wall
CFLAGS=$(COMMONFLAGS) -DDEBUG

SRC=src
SRCS=$(wildcard $(SRC)/*.c)

OBJ=obj
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

BINDIR=bin
BIN=$(BINDIR)/nanofuzz


all: $(BIN)


release: CFLAGS=$(COMMONFLAGS) -O3 -DNDEBUG
release: clean
release: $(BIN)


clean:
	-rm -r $(BINDIR)/* $(OBJ)/*


$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


$(BIN): $(OBJS)
	-mkdir $(BINDIR)
	-mkdir $(OBJ)
	-rm $(BIN)
	$(CC) $(CFLAGS) $(OBJS) -o $@
