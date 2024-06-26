#ifndef TCL_TEST_SUBST_H
#define TCL_TEST_SUBST_H

static void check_eval(struct tcl *tcl, const char *s, const char *expected) {
  int destroy = 0;
  struct tcl tmp;
  if (tcl == NULL) {
    tcl_init(&tmp, NULL);
    tcl = &tmp;
    destroy = 1;
  } else {
    tcl_errorinfo(tcl, NULL);  /* make sure to clear error info. */
  }
  if (tcl_eval(tcl, s, strlen(s) + 1) == FERROR) {
    FAIL("eval returned error: %s, (%s)\n", tcl_errorinfo(tcl, NULL), s);
  } else if (strcmp(tcl_data(tcl->result), expected) != 0) {
    FAIL("Expected %s, but got %s. (%s)\n", expected, tcl_data(tcl->result),
         s);
  } else {
    printf("OK: %s -> %s\n", s, expected);
  }
  if (destroy) {
    tcl_destroy(tcl);
  }
}

static void test_subst() {
  printf("\n");
  printf("###################\n");
  printf("### SUBST TESTS ###\n");
  printf("###################\n");
  printf("\n");

  check_eval(NULL, "subst hello", "hello");
  check_eval(NULL, "subst {hello}", "hello");
  check_eval(NULL, "subst {hello world}", "hello world");
  check_eval(NULL, "subst {hello {world}}", "hello {world}");

  //check_eval(NULL, "subst $foo", ""); // TR: this fails because using a variable before it is set, is now an error

  struct tcl tcl;
  tcl_init(&tcl, NULL);
  tcl_var(&tcl, "foo", tcl_value("bar", 3));
  tcl_var(&tcl, "bar", tcl_value("baz", 3));
  tcl_var(&tcl, "baz", tcl_value("Hello", 5));
  check_eval(&tcl, "subst $foo", "bar");
  check_eval(&tcl, "subst $foo[]$foo", "barbar");
  check_eval(&tcl, "subst $$foo", "baz");
  check_eval(&tcl, "subst [set $foo]", "baz");
  check_eval(&tcl, "subst $[set $foo]", "Hello");
  check_eval(&tcl, "subst $$$foo", "Hello");
  tcl_destroy(&tcl);

  check_eval(NULL, "subst {hello}{world}", "helloworld");
  check_eval(NULL, "subst hello[subst world]", "helloworld");
  check_eval(NULL, "subst hello[\n]world", "helloworld");

  /* Example from Picol */
  check_eval(NULL, "set a su; set b bst; $a$b Hello", "Hello");
  /* This is an error in TCL, but works in Picol */
  check_eval(NULL, "set foo {hello world}", "hello world");
  check_eval(NULL,
             "set foo {hello world}; set bar \"qux $foo\"; subst $foo$bar",
             "hello worldqux hello world");
  check_eval(NULL, "set a f; set b {o}; set $a$b$b [subst \"hello\"]; set foo",
             "hello");
  check_eval(NULL, "set {a \"b\"} hello; subst ${a \"b\"}", "hello");
  check_eval(NULL, "set \"a b\" hello; subst ${a b}", "hello");

  check_eval(NULL, "set q {\"}; set msg hello; subst $q$msg$q", "\"hello\"");
  check_eval(NULL, "set q {\"}; subst $q[]hello[]$q", "\"hello\"");
  check_eval(NULL, "set x {\n\thello\n}", "\n\thello\n");

  /* Some puts commands */
  check_eval(NULL, "set abc {[}[]hello[]{]}", "[hello]");
  check_eval(NULL, "set abc {{hello}}", "{hello}");

  /* XXX most command involving unpaired braces (e.g. in quotes) don't work
   * because of the dirty list implementation */
}

#endif /* TCL_TEST_SUBST_H */
