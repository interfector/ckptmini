CC = gcc
CFLAGS = -I./include

TARGET = ckptmini
SOURCES = pmparser.c utils.c core.c commands.c elfsym.c main.c
OBJECTS = $(SOURCES:.c=.o)

PARASITE = parasite.elf
PARASITE_BIN = parasite.bin
PARASITE_OBJ = parasite_blob.o

TEST_TARGETS = tests/test_loop tests/test_call tests/test_thread tests/test_collider tests/test_static tests/test_finish tests/test_leaf
TEST_SOURCES = tests/test_loop.c tests/test_call.c tests/test_thread.c tests/test_collider.c tests/test_static.c tests/test_finish.c tests/test_leaf.c
TEST_OBJS = $(TEST_SOURCES:.c=.o)

TESTLIB = testlib.so
TESTLIB_SRC = tests/testlib.c

HIJACKLIB = hijacklib.so
HIJACKLIB_SRC = tests/hijacklib.c

.PHONY: all clean test parasite

all: $(TARGET)

$(TARGET): $(OBJECTS) $(PARASITE_OBJ)
	$(CC) $(OBJECTS) $(PARASITE_OBJ) -o $(TARGET) -lcapstone

$(PARASITE_OBJ): $(PARASITE_BIN)
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 $(PARASITE_BIN) $(PARASITE_OBJ)

$(PARASITE_BIN): parasite.c
	gcc -nostdlib -nodefaultlibs -fpic -fno-stack-protector -o $(PARASITE) parasite.c
	objcopy -O binary --only-section=.text $(PARASITE) $(PARASITE_BIN)

parasite: $(PARASITE_BIN)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGETS) $(TESTLIB) $(HIJACKLIB)

tests: all test_loop test_call test_thread test_static test_finish test_leaf $(TESTLIB) $(HIJACKLIB)
	./tests/test_ckptmini.sh

$(TESTLIB): $(TESTLIB_SRC)
	gcc -shared -fPIC -fno-stack-protector -nostdlib -o tests/testlib.so $<

$(HIJACKLIB): $(HIJACKLIB_SRC)
	gcc -shared -fPIC -o tests/hijacklib.so $< -Wl,-u,printf

test_loop: tests/test_loop.o
	$(CC) $< -o tests/test_loop

test_call: tests/test_call.o
	$(CC) $< -o tests/test_call

test_thread: tests/test_thread.o
	$(CC) $< -pthread -o tests/test_thread

test_collider: tests/test_collider.o
	$(CC) $< -o tests/test_collider

test_static: tests/test_static.o
	$(CC) $< -o tests/test_static

test_finish: tests/test_finish.o
	$(CC) $< -o tests/test_finish

test_leaf: tests/test_leaf.o
	$(CC) $< -o tests/test_leaf

# test_leaf must be -O2 so hotloop is a frameless leaf while main keeps its
# frame pointer (via the optimize() attribute on main).
tests/test_leaf.o: tests/test_leaf.c
	$(CC) $(CFLAGS) -O2 -c $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TEST_TARGETS) $(TEST_OBJS) tests/testlib.so tests/hijacklib.so $(TARGET)
	rm -f $(PARASITE) $(PARASITE_BIN) $(PARASITE_OBJ)

PREFIX ?= /usr/local
INSTALL_DIR = $(DESTDIR)$(PREFIX)/bin

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	cp $(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)
