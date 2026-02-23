CC = gcc
CFLAGS = -I./include

TARGET = ckptmini
SOURCES = pmparser.c utils.c core.c commands.c main.c
OBJECTS = $(SOURCES:.c=.o)

TEST_TARGETS = tests/test_loop tests/test_call
TEST_SOURCES = tests/test_loop.c tests/test_call.c
TEST_OBJS = $(TEST_SOURCES:.c=.o)

TESTLIB = testlib.so
TESTLIB_SRC = tests/testlib.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGETS) $(TESTLIB)

tests: all test_loop test_call $(TESTLIB)
	./tests/test_ckptmini.sh

$(TESTLIB): $(TESTLIB_SRC)
	gcc -shared -fPIC -fno-stack-protector -nostdlib -o tests/testlib.so $<

test_loop: tests/test_loop.o
	$(CC) $< -o tests/test_loop

test_call: tests/test_call.o
	$(CC) $< -o tests/test_call

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TEST_TARGETS) $(TEST_OBJS) tests/testlib.so $(TARGET)
