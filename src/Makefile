CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -std=c99

OBJS = mem.o util.o main.o

all: allocator_test

allocator_test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

mem.o: mem.c mem.h mem_internals.h util.h
	$(CC) $(CFLAGS) -c mem.c

util.o: util.c util.h
	$(CC) $(CFLAGS) -c util.c

main.o: main.c mem.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f *.o allocator_test
