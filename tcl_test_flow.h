#ifndef TCL_TEST_FLOW_H
#define TCL_TEST_FLOW_H

static void test_flow() {
  printf("\n");
  printf("##########################\n");
  printf("### CONTROL FLOW TESTS ###\n");
  printf("##########################\n");
  printf("\n");

  check_eval(NULL, "if {1 < 2} {puts A} {puts B}", "A");
  check_eval(NULL, "if {1 > 2} {puts A} {puts B}", "B");
  check_eval(NULL, "if {1 > 2} {puts A}", "0");

  check_eval(NULL,
             "set x 0; if {$x == 0} {subst A} {$x == 1} {subst B} {subst C}",
             "A");
  check_eval(NULL,
             "set x 1; if {$x == 0} {subst A} {$x == 1} {subst B} {subst C}",
             "B");
  check_eval(NULL,
             "set x 2; if {$x == 0} {subst A} {$x == 1} {subst B} {subst C}",
             "C");

  struct tcl tcl;
  tcl_init(&tcl);
  check_eval(&tcl, "set x 0", "0");
  check_eval(&tcl, "while {$x < 5} {set x [expr $x + 1]}", "0");
  check_eval(&tcl, "set x 0", "0");
  check_eval(&tcl, "while {1 == 1} {set x [expr $x + 1]; if {$x == 5} {break}}",
             "break");
  check_eval(&tcl, "set x 0", "0");
  check_eval(
      &tcl,
      "while {1 == 1} {set x [expr $x + 1]; if {$x != 5} {continue} ; return foo}",
      "foo");
  check_eval(NULL, "proc foo {} { subst hello }; foo", "hello");
  check_eval(NULL, "proc five {} {set r [expr 2 + 3]}; five", "5");
  check_eval(NULL, "proc foo {a} { subst $a }; foo hello", "hello");
  check_eval(NULL, "proc foo {} { subst hello; return A; return B;}; foo", "A");
  check_eval(NULL, "set x 1; proc two {} { set x 2;}; two; subst $x", "1");
  /* Example from Picol */
  check_eval(NULL, "proc fib {x} { if {$x <= 1} {return 1} "
                   "{ return [expr [fib [expr $x - 1]] + [fib [expr $x - 2]]]}}; fib 20",
             "10946");

  check_eval(&tcl, "proc square {x} { return [expr $x * $x] }; square 7", "49");
  check_eval(&tcl, "set a 4", "4");
  check_eval(&tcl, "square $a", "16");
  check_eval(&tcl, "subst \"$a[]*$a ?\"", "4*4 ?");
  check_eval(&tcl, "subst \"I can compute that $a[]x$a = [square $a]\"",
             "I can compute that 4x4 = 16");
  check_eval(&tcl, "set a 1", "1");
  check_eval(&tcl, "while {$a <= 10} { puts \"$a [expr $a == 5]\";"
                   "if {$a == 5} { puts {Missing five!}; set a [expr $a + 1]; "
                   "continue;}; puts \"I can compute that $a[]x$a = [square "
                   "$a]\" ; set a [expr $a + 1]}",
             "0");

  tcl_destroy(&tcl);
}

#endif /* TCL_TEST_FLOW_H */
