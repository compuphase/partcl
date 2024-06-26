CC ?= clang
CFLAGS ?= -Os -Wall -Wextra -std=c11 -pedantic
LDFLAGS ?= -Os

TCLBIN := tcl

TEST_CC := clang
TEST_CFLAGS := -O0 -g -std=c11 -pedantic -fprofile-arcs -ftest-coverage
TEST_LDFLAGS := $(TEST_CFLAGS)
TCLTESTBIN := tcl_test

all: $(TCLBIN) test
tcl: tcl.o
	$(CC) $(LDFLAGS) $< -lbsd

test: $(TCLTESTBIN)
	./tcl_test
$(TCLTESTBIN): tcl_test.o
	$(TEST_CC) $(TEST_LDFLAGS) -o $@ $^ -lbsd
tcl_test.o: tcl_test.c tcl.c \
	tcl_test_lexer.h tcl_test_subst.h tcl_test_flow.h tcl_test_math.h
	$(TEST_CC) $(TEST_CFLAGS) -c tcl_test.c -o $@

coverage: test
	gcov tcl_test.c

fmt:
	clang-format-3.6 -i *.c *.h
	cloc tcl.c

clean:
	rm -f $(TCLBIN) $(TCLTESTBIN) *.o *.gcda *.gcno

.PHONY: test clean fmt
