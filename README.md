# ParTcl - a minimal Tcl interpreter

Note: This is a fork; see https://github.com/zserge/partcl for the original.

In 1988, John Ousterhout developed Tcl with the goal to be a light-weight extension
language for applications; a "macro language", so to speak. It has grown
significantly, and is now often used to create complete tools or utilities in.

ParTcl reverts back to the roots of Tcl: ParTcl's goal is to be easily embeddable
in applications, and function as an extension language for these applications.
In pursuit of simplicitly and compactness of the implementation, ParTcl is closer
to the original versions of Tcl (pre 7.0), in syntax and is semantics, than to
the lastest release (8.6, at the time of writing).

Therefore, if you wish to pick up a book on Tcl, in order to make better use of
ParTcl, old books are fine. See, for example, "[Tcl and the Tk Toolkit](http://csis.pace.edu/~benjamin/software/book1.pdf)"
by John Ousterhout, and which is available for free.

## Features

* Easily embeddable, plain C99 code (one C file, one H file).
* No external dependencies, apart from the standard C library.
* Good test coverage.
* Flexible and easy-to-use interface to C/C++ programs, can be extended with custom Tcl commands.
* Runs well on bare metal embedded MCUs (though, dynamic memory allocation of some kind, &agrave;-la malloc() &amp; free(), is required).
* Arithmetic in 64-bit integers.

## Usage

The API is documented in the `tcl.h` file.

```c
struct tcl tcl;
const char *script = "set x 4; puts [expr 2 + $x * 10]";

tcl_init(&tcl);
if (tcl_eval(&tcl, script, strlen(script)) != FERROR) {
    struct tcl_value *retval = tcl_return(&tcl);
    printf("Return: %.*s\n", tcl_length(retval), tcl_data(retval));
} else {
    int code, line;
    const char *msg = tcl_errorpos(&tcl, &code, &line, NULL, 0);
    printf("Error [%d] %s on or after line %d\n", code, msg, line);
}
tcl_destroy(&tcl);
```

There are a few key concepts in ParTcl: values, lists and variables.

### Values

A "value" is a string, as used internally by ParTcl. It can be used as
a C-language string (it is zero-terminated). However, it may contain
embedded zero bytes (in case the Tcl script works on binary data), so it
is safer to explicitly get the length. Values are allocated dynamically.
You create a value with `tcl_value()` and delete it with `tcl_free()`.

Function `tcl_data()` returns a pointer to the byte string, `tcl_length()`
its length. You should not modify the contents directly; instead, you
create a new value and delete the old one. The raw data of a value may
move in memory; you should therefore not cache the pointer returned by
`tcl_data()` either.

An exception to the "don't modify a value" rule, is that you can append a
value to another with `tcl_append()`. The `tcl_append()` function modifies
the primary value (first argument) and deletes the "tail" argument.

```
/* Raw string values */
struct tcl_value *tcl_value(const char *data, size_t len);
struct tcl_value *tcl_dup(struct tcl_value *value);
bool tcl_append(struct tcl_value *value, struct tcl_value *tail);
struct tcl_value *tcl_free(struct tcl_value *value);

/* Helpers to access raw string or numeric value */
const char *tcl_data(struct tcl_value *value);
int tcl_length(struct tcl_value *value);
bool tcl_isnumber(const struct tcl_value *valuealue);
tcl_int tcl_number(struct tcl_value *value);
```

Functions `tcl_isnumber()` and `tcl_number()` are helper functions to check
whether a value represents a (decimal) number and the numberic value of that
number, respectively. The `tcl_int` type is declared in `tcl.h` as a `long long`
(64-bit integer), but you can adjust this to `long` or another type.

### Lists

A list is a string, as is common in Tcl. Thus, in ParTcl, a list is a "value".
There are a few special functions on lists, however, that make sure that the
list is well-formed. You start a new (empty) list with `tcl_list_new()` and
add items to it with `tcl_list_append()`. Function `tcl_list_append()` takes
two parameters: a list and a value to append. After the call, the value is
*owned* by the list, and you should therefore not free the item.

When done, the entire list is freed with `tcl_free()`, just like values.

```
/* List values */
struct tcl_value *tcl_list_new();
struct tcl_value *tcl_list_append(struct tcl_value *value, struct tcl_value *tail);
struct tcl_value *tcl_list_item(struct tcl_value *value, int index);
int tcl_list_length(struct tcl_value *value);
```

In the default implementation lists are implemented as raw strings that add
some escaping (braces) around each item (lists thus resemble Tcl source code).
It's a simple solution that also reduces the code, but in some exotic cases the
escaping can go wrong and invalid results will be returned.

### Variables

A variable holds a value. Or in the case of an array, a variable holds multiple
values. You create a variable with `tcl_var()`. Currently, you should do this
before `tcl_eval()` (and after `tcl_init()`). This creates a global variable.
When you create C functions that you register to ParTcl as commands, and you
would create a variable in that function (when it is called), that variable will
be a local variable.

When you create a variable, you pass a value as its content. After the call, the
value is *owned* by the variable. You must not free the value.

You also use `tcl_var()` to have it return its value. Note that the returned value
may not be modified and should not be cached (as a pointer). You can, of course, make
a local copy of the value.

There is currently no function to delete a single variable. Calling `tcl_destroy()`
removes all variables (and you should then call `tcl_init()` again).

## Language syntax

Tcl script is made up of _commands_ separated by semicolons or newline
symbols. Commands in their turn are made up of _fields_ separated by whitespace.
A word is a field, as long as it does not contain a space character. To make
whitespace a part of the field one may use double quotes or curly braces.

An important part of the language is _command substitution_, when the result of
a command inside square braces is returned as a part of the outer command, e.g.
`puts [expr 1 + 2]`. Apart from command substitution, Tcl also knows _variable substitution_.
However, command and variable substitution does _not_ happen inside fields that
are enveloped in curly braces.

The only data type of the language is a string. When a variable (or field) contains
only digits, it may be implicitly interpreted as a number (specifically in the `expr`
builtin command), but that same variable can still be used in string operations.

## Builtin commands

| name     | summary |
| ------   | ------- |
| append   | Append contents to a variable (concatenate strings). |
| array    | Functions on array variables: `length` (same as `size`) and `slice`. |
| binary   | Binary-to-integer conversion (and vice versa), width subcommands `format` and `scan`. This command can be disabled using `#define TCL_DISABLE_BINARY`, for implementations that do not need to handle binary data. |
| break    | Abort a loop, jumps to the first instruction following the loop. |
| clock    | Time query and formatting functions, with subcommands `seconds` and `format`. This command can be disabled using `#define TCL_DISABLE_CLOCK`, for any context where it does not make sense. |
| close    | Close a file. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| concat   | Join multiple lists into a single list. |
| continue | Skip the remainder of the loop body, jumps back to the condition of the loop. |
| eof      | Check whether End-Of-File has been reached. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| exit     | End the script with an optional return code. Note that this command aborts the script, but not the program that ParTcl is embedded in. |
| expr     | Interpret the infix expression that follows. This is and integer-only expression parser, but supporting most of the Tcl operator set, with the same precedence levels as standard Tcl. Missing are: the conditional operator (`? :`), list operators `in` and `ni`, and functions. |
| for      | Run a loop `for {setup} {condition} {post} {body}`. One may use `break`, `continue` (or `return`) inside the loop to contol the flow. |
| foreach  | Run a loop over all elements in a list. |
| format   | Format a string with placeholders, similar to `sprintf` in C. Currently only `%c`, `%d`, `%i`, `%x` and `%s` are supported, plus optional "padding" and "alignment" modifiers (e.g. `%04x` or `%-20s`). |
| gets     | Read a line for a file. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| global   | Mark any variable following it as a global variable. There may be a list of names, separated by spaces. Each name may not exists locally, and must already exists as a global variable. |
| if       | Conditional execution, `if {cond} {then} {cond2} {then2} {else}`. |
| incr     | Increment or decrements a variable. |
| info     | Return some information on the Tcl interpreter, with subcommands `exists` and `tclversion`. Notably, `info exists var` returns 1 if the variable exists, and 0 otherwise. |
| join     | Create a string from a list, by concatenating elements, with a separator chosen by the user. |
| lappend  | Append values to a variable (where the variable is presumed to contain a list). |
| lindex   | Return a specified element from the list. |
| list     | Create a list from the values that follow it. |
| llength  | Return the number of elements in a list. |
| lrange   | Return a subset of a source list as a new list. |
| lreplace | Delete a range of elements in a list and inserts a new set of elements at that position. |
| open     | Open a file. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| proc     | Create a new command appending it to the list of current interpreter commands. That's how user-defined commands are built. |
| puts     | Print argument to the stdout, followed by a newline. This command can be disabled using both `#define TCL_DISABLE_PUTS` (for "stdout") and `#define TCL_DISABLE_FILEIO` (for output to file). |
| read     | Read a file competely in memory. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| return   | Jump out of the current command (`proc`), with an optional explicit return value. |
| scan     | Parse a string and stores extracted values into variables. This command currently only supports `%c`, `%d`, `%i` and `%x` placeholders, plus optional "width" modifiers (e.g. `%2x`). |
| seek     | Set file read/write position. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| set      | Assign value to the variable and/or returns the current variable value. |
| split    | Create a list from a string, by splitting the string on a separator chosen by the user. |
| string   | An assortment of string functions: `compare`, `equal`, `first`, `index`, `last`, `length`, `match`, `range`, `tolower`, `toupper`, `trim`, `trimleft`, `trimright`. |
| subst    | Perform command and variable substitution in the argument string. |
| switch   | Control flow structure, executing a block selected from matching one out of several patterns. |
| tell     | Get the current file read/write position. This command can be disabled using `#define TCL_DISABLE_FILEIO`, which is handy for embedded systems without file system. |
| unset    | Clear a variable (remove it completely). |
| upvar    | Create an alias for a variable at a different scope, e.g. to implement pass-by-reference arguments. |
| while    | Run a loop as long as the condition is true; `while {cond} {body}`. If the condition is already false on start, the body is never evaluated. One may use `break`, `continue` (or `return`) inside the loop to contol the flow. |

## Operator table

These are the operators that can be used in the parameter of the `expr` command. The expression evaluator in ParTcl is integer-only.

| operator       | summary |
| -------------- | ------- |
| `-` `+` `!` `~` `()` | unary operators: negate, unary plus (a no-operation operator), logic not, binary invert, and sub-expressions between parentheses |
| `**`           | exponentiation |
| `*` `/` `%`    | multiply, divide, remainder after division |
| `+` `-`        | addition, subtraction |
| `<<` `>>`      | binary shift left & right |
| `<` `<=` `>` `>=` | smaller than, smaller than or equal, greater than, greater than or equal |
| `==` `!=`      | equal, not equal |
| `&`            | binary and |
| `^`            | binary exclusive or |
| `\|`           | binary or |
| `&&`           | logic and |
| `\|\|`         | logic or |
| `? :`          | conditional selection (ternary operator) |

ParTcl (like Tcl) uses *floored* integer division, in the sense that the remainder after
division is always a positive value, and the following relation holds:
```
    v2 * (v1 / v2) + (v1 % v2) == v1
```
For positive numerators &amp; denominators, floored division gives the same results as the (more common) *truncated* division: the division `14 / 3` is `4` (and with remainder `2`).
The difference is with negative results: with truncated division `-14 / 3` equals `-4` with remainder `-2`, but with floored division, `-14 / 3` equals `-5` with remainder `1`.

# Internals

## Lexer

Any symbol can be part of the word, except for the following special symbols:

* whitespace, tab - used to delimit words
* `\r`, `\n`, semicolon or EOS (zero-terminator) - used to delimit commands
* Braces, square brackets, dollar sign - used for substitution and grouping

ParTcl has special helper functions for these char classes:

```
static bool tcl_is_space(char c);
static bool tcl_is_end(char c);
static bool tcl_is_special(char c, bool quote);
```

`tcl_is_special` behaves differently depending on the quoting mode (`quote`
parameter). Inside a quoted string braces, semicolon and end-of-line symbols
lose their special meaning and become regular printable characters.

ParTcl lexer is implemented in one function:

```
int tcl_next(const char *list, size_t length, const char **from, const char **to, unsigned *flags);
```

`tcl_next` function finds the next token in the string `list`. Paramters `from` and `to` are
set to point to the token start/end. Parameter `flags` holds flags for the quoting mode
(toggled if `"` is met), and marks whether a comment is allowed (and must be gobbled), plus
other(s). When calling the lexer from your own code, `flags` should be initialized to `0`.

A special macro `tcl_each(s, len, skip_error)` can used to iterate over all the
tokens in the string. If `skip_error` is false - loop ends when string ends,
otherwise loop can end earlier if a syntax error is found. It allows to
"validate" input string without evaluating it and detect when a full command
has been read.

## Memory management

Tcl uses strings as a primary data type. When a Tcl script is evaluated, many of
the strings are created, disposed or modified. In embedded systems, memory
management can be complex, so all operations with Tcl values are moved into
isolated functions that can be rewritten to optimize certain parts (e.g.
to use a pool of strings, a custom memory allocator, cache numerical or list
values to increase performance etc).

```
/* Functions calling malloc() or free() */
struct tcl_value *tcl_value(const char *data, size_t len);
bool tcl_append(struct tcl_value *value, struct tcl_value *tail);
bool tcl_list_append(struct tcl_value *list, struct tcl_value *tail);
struct tcl_value *tcl_free(struct tcl_value *value);
struct tcl_value *tcl_var(struct tcl *tcl, const char *name, struct tcl_value *value);
void tcl_destroy(struct tcl *tcl);

/* Internal functions also doing memory allocation */
static struct tcl_env *tcl_env_alloc(struct tcl_env *parent);
static struct tcl_var *tcl_env_var(struct tcl_env *env, const char *name);
static struct tcl_env *tcl_env_free(struct tcl_env *env);
static void tcl_var_free_values(struct tcl_var *var);
static void tcl_var_free(struct tcl_env *env, struct tcl_var *var);
```

## Environments

A special type, `struct tcl_env` is used to keep the evaluation environment (a
set of functions). The interpreter creates a new environment for each
user-defined procedure, also there is one global environment per interpreter.

There are only 3 functions related to the environment. One creates a new environment,
another seeks for a variable (or creates a new one), the last one destroys the environment
and all its variables.

These functions use malloc()/free(), but can easily be rewritten to use memory pools instead.

```
static struct tcl_env *tcl_env_alloc(struct tcl_env *parent);
static struct tcl_var *tcl_env_var(struct tcl_env *env, tcl_value_t *name);
static struct tcl_env *tcl_env_free(struct tcl_env *env);
```

Variables are implemented as a single-linked list, each variable is a pair of
values (name + value) and a pointer to the next variable.

## Interpreter

ParTcl interpreter is a simple structure `struct tcl` which keeps the current
environment, array of available commands and a last result value.

Interpreter logic is wrapped around two functions - evaluation and
substitution.

Substitution:

- If argument starts with `$` - evaluate the name that follows and return
  the variable's value. If the variable does not exist, an empty variable is
  created.
- If argument starts with `[` - evaluate what's inside the square brackets and
  return the result.
- If argument is a quoted string (e.g. `{foo bar}`) - return it as is, just
  without braces.
- Otherwise return the argument as is.

Evaluation:

- Iterates over each token in a list
- Appends words into a list
- If the command end is met (semicolon, or newline, or end-of-file - our lexer
  has a special token type `TCMD` for them) - then find a suitable command (the
  first word in the list) and call it.

Where the commands are taken from? Initially, a ParTcl interpeter starts with
no commands, but one may add the commands by calling `tcl_register()`.

Each command has a name, arity (how many arguments it shall take - interpreter
checks it before calling the command, use zero arity for varargs) and a C
function pointer that actually implements the command.

## Building and testing

All sources are in one file, `tcl.c`. It can be used as a standalone
interpreter, or made part of a bigger application. The structure declarations
and function prototypes are in tcl.h.

Tests are run with clang and coverage is calculated. Just run "make test" and
you're done.

Code is formatted using clang-format to keep the clean and readable coding
style. Please run it for pull requests, too.

## License

Code is distributed under MIT license, feel free to use it in your proprietary
projects as well.

