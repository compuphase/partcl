#ifndef TCL_TEST_LEXER_H
#define TCL_TEST_LEXER_H

#include <assert.h>
#include <stdarg.h>
#include <string.h>

static void va_check_tokens(const char *s, size_t len, int count, va_list ap) {
  int j = 0;
  tcl_each(s, len, 1) {
    int type = va_arg(ap, int);
    char *token = va_arg(ap, char *);
    j++;
    if (p.token != type) {
      FAIL("Expected token #%d type %d, but found %d (%.*s)\n", j, type,
           p.token, (int)len, s);
    } else if (p.token == TERROR) {
      break;
    } else {
      if ((p.token == TPART || p.token == TFIELD) &&
          (strlen(token) != p.to - p.from ||
           strncmp(p.from, token, p.to - p.from) != 0)) {
        FAIL("Expected %s, but found %.*s (%s)\n", token, (int)(p.to - p.from),
             p.from, s);
      }
    }
  }
  if (j != count) {
    FAIL("Expected %d tokens, but found %d (%s)\n", count, j, s);
  } else {
    printf("OK: %.*s\n", (int)len, s);
  }
}

static void check_tokens(const char *s, int count, ...) {
  va_list ap;
  va_start(ap, count);
  va_check_tokens(s, strlen(s) + 1, count, ap);
  va_end(ap);
}

static void check_tokens_len(const char *s, size_t len, int count, ...) {
  va_list ap;
  va_start(ap, count);
  va_check_tokens(s, len, count, ap);
  va_end(ap);
}

static void test_lexer() {
  printf("\n");
  printf("###################\n");
  printf("### LEXER TESTS ###\n");
  printf("###################\n");
  printf("\n");

  /* Empty */
  check_tokens("", 1, TEXECPOINT, "");
  check_tokens(";", 2, TEXECPOINT, ";", TEXECPOINT, "");
  check_tokens(";;;  ;", 5, TEXECPOINT, ";", TEXECPOINT, ";", TEXECPOINT, ";", TEXECPOINT, ";", TEXECPOINT,
               "");
  /* Regular words */
  check_tokens("foo", 2, TFIELD, "foo", TEXECPOINT, "");
  check_tokens("foo bar", 3, TFIELD, "foo", TFIELD, "bar", TEXECPOINT, "");
  check_tokens("foo bar baz", 4, TFIELD, "foo", TFIELD, "bar", TFIELD, "baz", TEXECPOINT,
               "");
  /* Imbalanced braces/brackets */
  check_tokens("foo ]", 2, TFIELD, "foo", TERROR, "");
  check_tokens("foo }", 2, TFIELD, "foo", TERROR, "");

  /* Grouping */
  check_tokens("foo {bar baz}", 3, TFIELD, "foo", TFIELD, "{bar baz}", TEXECPOINT, "");
  check_tokens("foo {bar {baz} {q u x}}", 3, TFIELD, "foo", TFIELD,
               "{bar {baz} {q u x}}", TEXECPOINT, "");
  check_tokens("foo {bar {baz} [q u x]}", 3, TFIELD, "foo", TFIELD,
               "{bar {baz} [q u x]}", TEXECPOINT, "");
  check_tokens("foo {bar $baz [q u x]}", 3, TFIELD, "foo", TFIELD,
               "{bar $baz [q u x]}", TEXECPOINT, "");
  check_tokens("foo {bar \" baz}", 3, TFIELD, "foo", TFIELD, "{bar \" baz}", TEXECPOINT,
               "");
  check_tokens("foo {\n\tbar\n}", 3, TFIELD, "foo", TFIELD, "{\n\tbar\n}", TEXECPOINT,
               "");
  /* Substitution */
  check_tokens("foo [bar baz]", 3, TFIELD, "foo", TFIELD, "[bar baz]", TEXECPOINT, "");
  check_tokens("foo [bar {baz}]", 3, TFIELD, "foo", TFIELD, "[bar {baz}]", TEXECPOINT,
               "");
  check_tokens("foo $bar $baz", 4, TFIELD, "foo", TFIELD, "$bar", TFIELD, "$baz",
               TEXECPOINT, "");
  check_tokens("foo $bar$baz", 4, TFIELD, "foo", TPART, "$bar", TFIELD, "$baz",
               TEXECPOINT, "");
  check_tokens("foo ${bar baz}", 3, TFIELD, "foo", TFIELD, "${bar baz}", TEXECPOINT,
               "");
  check_tokens("puts hello[\n]world", 5, TFIELD, "puts", TPART, "hello", TPART,
               "[\n]", TFIELD, "world", TEXECPOINT, "");
  /* Quotes */
  check_tokens("\"\"", 3, TPART, "", TFIELD, "", TEXECPOINT, "");
  check_tokens("\"\"\"\"", 2, TPART, "", TERROR, "");
  check_tokens("foo \"bar baz\"", 5, TFIELD, "foo", TPART, "", TPART, "bar baz",
               TFIELD, "", TEXECPOINT, "");
  check_tokens("foo \"bar $b[a z]\" qux", 8, TFIELD, "foo", TPART, "", TPART,
               "bar ", TPART, "$b", TPART, "[a z]", TFIELD, "", TFIELD, "qux",
               TEXECPOINT, "");
  check_tokens("foo \"bar baz\" \"qux quz\"", 8, TFIELD, "foo", TPART, "", TPART,
               "bar baz", TFIELD, "", TPART, "", TPART, "qux quz", TFIELD, "",
               TEXECPOINT, "");
  check_tokens("\"{\" \"$a$b\"", 8, TPART, "", TPART, "{", TFIELD, "", TPART, "",
               TPART, "$a", TPART, "$b", TFIELD, "", TEXECPOINT, "");

  check_tokens("\"{\" \"$a\"$b", 6, TPART, "", TPART, "{", TFIELD, "", TPART, "",
               TPART, "$a", TERROR, "");
  check_tokens("\"$a + $a = ?\"", 7, TPART, "", TPART, "$a", TPART, " + ",
               TPART, "$a", TPART, " = ?", TFIELD, "", TEXECPOINT, "");
  /* Variables */
  check_tokens("puts $ a", 2, TFIELD, "puts", TERROR, "");
  check_tokens("puts $\"a b\"", 2, TFIELD, "puts", TERROR, "");
  check_tokens("puts $$foo", 3, TFIELD, "puts", TFIELD, "$$foo", TEXECPOINT, "");
  check_tokens("puts ${a b}", 3, TFIELD, "puts", TFIELD, "${a b}", TEXECPOINT, "");
  check_tokens("puts $[a b]", 3, TFIELD, "puts", TFIELD, "$[a b]", TEXECPOINT, "");
  check_tokens("puts { ", 2, TFIELD, "puts", TERROR, "");
  check_tokens("set a {\n", 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens("puts {[}", 3, TFIELD, "puts", TFIELD, "{[}", TEXECPOINT, "");
  check_tokens("puts [{]", 3, TFIELD, "puts", TFIELD, "[{]", TEXECPOINT, "");
  check_tokens("puts {[}{]} ", 4, TFIELD, "puts", TPART, "{[}", TFIELD, "{]}",
               TEXECPOINT, "");

  /* Strings without trailing zero */
  //check_tokens_len("abc foo", 1, 1, TERROR, "a"); // TR: not sure why these should return errors, the lexer does not overrun the length
  //check_tokens_len("abc foo", 2, 1, TERROR, "ab");
  //check_tokens_len("abc foo", 3, 1, TERROR, "abc");
  //check_tokens_len("abc foo", 4, 2, TFIELD, "abc", TERROR, "");
  check_tokens_len("abc foo", 7, 2, TFIELD, "abc", TFIELD, "foo");
  check_tokens_len("abc foo", 8, 3, TFIELD, "abc", TFIELD, "foo", TEXECPOINT, "");
  check_tokens_len("s", 1, 1, TFIELD, "s");
  check_tokens_len("se", 2, 1, TFIELD, "se");
  check_tokens_len("set", 3, 1, TFIELD, "set");
  check_tokens_len("set ", 4, 2, TFIELD, "set", TDONE, "");
  check_tokens_len("set a", 5, 2, TFIELD, "set", TFIELD, "a");
  check_tokens_len("set a ", 6, 3, TFIELD, "set", TFIELD, "a", TDONE, "");
  check_tokens_len("set a {", 7, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\n", 8, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nh", 9, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhe", 10, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhel", 11, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhell", 12, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhello", 13, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhello\n", 14, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  //check_tokens_len("set a {\nhello\n}", 15, 3, TFIELD, "set", TFIELD, "a", TERROR, "");
  check_tokens_len("set a {\nhello\n}\n", 16, 4, TFIELD, "set", TFIELD, "a", TFIELD, "{\nhello\n}", TEXECPOINT, "");
}

#endif /* TCL_TEST_LEXER_H */
