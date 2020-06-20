CFLAGS = -O1
CC=clang

.PHONY: all
all: fizz_buzz fibonacci count_to hello_world

fizz_buzz: fizz_buzz.c
	$(CC) -o $@ $^ $(CFLAGS)

fibonacci: fibonacci.c
	$(CC) -o $@ $^ $(CFLAGS)

count_to: count_to.c
	$(CC) -o $@ $^ $(CFLAGS)

hello_world: hello_world.c
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm fizz_buzz fibonacci count_to hello_world
