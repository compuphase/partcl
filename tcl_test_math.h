#ifndef TCL_TEST_MATH_H
#define TCL_TEST_MATH_H

static void test_math() {
  printf("\n");
  printf("##################\n");
  printf("### MATH TESTS ###\n");
  printf("##################\n");
  printf("\n");

  check_eval(NULL, "subst [expr 1 < 2]", "1");
  check_eval(NULL, "subst [expr 1 < 1]", "0");
  check_eval(NULL, "subst [expr 1 <= 1]", "1");
  check_eval(NULL, "subst [expr 1 > 2]", "0");
  check_eval(NULL, "subst [expr 1 > 1]", "0");
  check_eval(NULL, "subst [expr 1 >= 1]", "1");
  check_eval(NULL, "subst [expr 1 == 1]", "1");
  check_eval(NULL, "subst [expr 1 != 1]", "0");

  check_eval(NULL, "subst [expr 1 + 2]", "3");
  check_eval(NULL, "subst [expr 4 * 2]", "8");
  check_eval(NULL, "subst [expr 7 - 2]", "5");
  check_eval(NULL, "subst [expr 7 / 2]", "3");
  check_eval(NULL, "subst [expr 4 ** 3]", "64");

  check_eval(NULL, "set a 5;set b 7; subst [expr 4 * ($a + $b) - 6]", "42");
}

#endif /* TCL_TEST_MATH_H */
