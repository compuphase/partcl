# ParTcl - a minimal Tcl interpreter

Note: This is a fork; see [https://github.com/zserge/partcl] for the original.

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

A "value" is a string, as used internally by ParTcl. It can be used as
a C-language string (it is zero-terminated). However, it may contain
embedded zero bytes (in case the Tcl script works on binary data), so it
is safer to explicitly get the length. Values are allocated dynamically.
You create a value with `tcl_value()` and delete it with `tcl_free()`.
Function `tcl_data()` returns a pointer to the byte string, `tcl_length()`
its length. You should not modify the contents directle; instead, you
create a new value and delete the old one. An exception is that you can
append a value to another with `tcl_append()`.

A list is a string, as is common in Tcl. Thus, in ParTcl, a list is a "value".
There are a few special functions on lists, however, that make sure that the
list is well-formed. You start a new (empty) list with `tcl_list_new()` and
add items to it with `tcl_list_append()`. Function `tcl_list_append()` takes
two parameters: a list and a value to append. After the call, the value is
*owned* by the list, and you should therefore not free the item.

When done, the entire list is freed with `tcl_free()`.

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

| name   | summary |
| ------ | ------- |
| append | Append contents to a variable (concatenate strings). |
| array  | Functions on array variables: `length` (same as `size`), `slice`. |
| break  | Aborts a loop, jumps to the first instruction following the loop. |
| concat | Joins multiple lists into a single list. |
| continue | Skips the remainder of the loop body, jumps back to the condition of the loop. |
| exit   | End the script with an optional return code. Note that this command aborts the script, but not the program that ParTcl is embedded in. |
| expr   | Interprets the infix expression that follows. This is and integer-only expression parser, but supporting most of the Tcl operator set, with the same precedence levels as standard Tcl. Missing are: the conditional operator (`? :`), list operators `in` and `ni`, and functions. |
| for    | Runs a loop `for {setup} {condition} {post} {body}`.  One may use `break`, `continue` (or `return`) inside the loop to contol the flow. |
| foreach | Runs a loop over all elements in a list. |
| format | Formats a string with placeholders, similar to `sprintf` in C. Currently only `%c`, `%d`, `%i`, `%x` and `%s` are supported, plus optional "padding" and "alignment" modifiers (e.g. `%04x` or `%-20s`). |
| global | Marks any variable following it as a global variable. There may be a list of names, separated by spaces. Each name may not exists locally, and must already exists as a global variable. |
| if     | Does a simple `if {cond} {then} {cond2} {then2} {else}`. |
| incr   | Increments or decrements a variable. |
| info   | Returns some information on the Tcl interpreter, with subcommands `exists` and `tclversion`. Notably, `info exists var` returns 1 if the variable exists, and 0 otherwise. |
| join   | Creates a string from a list, by concatenating elements, with a separator chosen by the user. |
| lappend | Appends values to a variable (where the variable is presumed to contain a list). |
| lindex | Returns a specified element from the list. |
| list   | Creates a list from the values that follow it. |
| llength | Returns the number of elements in a list. |
| lrange | Returns a subset of a source list as a new list. |
| lreplace | Deletes a range of elements in a list and inserts a new set of elements at that position. | 
| proc   | Creates a new command appending it to the list of current interpreter commands. That's how user-defined commands are built. |
| puts   | Prints argument to the stdout, followed by a newline. This command can be disabled using `#define TCL_DISABLE_PUTS`, which is handy for embedded systems that don't have "stdout". |
| return | Jumps out of the current command (`proc`), with an optional explicit return value. |
| scan   | Parses a string and stores extracted values into variables. This command currently only supports `%c`, `%d`, `%i` and `%x` placeholders, plus optional "width" modifiers (e.g. `%2x`). |
| set    | Assigns value to the variable and/or returns the current variable value. |
| split  | Creates a list from a string, by splitting the string on a separator chosen by the user. |
| string | An assortment of string functions: `compare`, `equal`, `first`, `index`, `last`, `length`, `match`, `range`, `tolower`, `toupper`, `trim`, `trimleft`, `trimright`. |
| subst  | Performs command and variable substitution in the argument string. |
| switch | Control flow structure, executing a block selected from matching one out of several patterns. |
| unset  | Clear a variable (remove it completely). |
| while  | Runs a loop as long as the condition is true; `while {cond} {body}`. If the condition is already false on start, the body is never evaluated. One may use `break`, `continue` (or `return`) inside the loop to contol the flow. |

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

## Data types

Tcl uses strings as a primary data type. When a Tcl script is evaluated, many of
the strings are created, disposed or modified. In embedded systems, memory
management can be complex, so all operations with Tcl values are moved into
isolated functions that can be easily rewritten to optimize certain parts (e.g.
to use a pool of strings, a custom memory allocator, cache numerical or list
values to increase performance etc).

```
/* Raw string values */
tcl_value_t *tcl_value(const char *data, size_t len, bool binary);
tcl_value_t *tcl_dup(tcl_value_t *v);
tcl_value_t *tcl_append(tcl_value_t *v, tcl_value_t *tail);
int tcl_length(tcl_value_t *v);
void tcl_free(tcl_value_t *v);

/* Helpers to access raw string or numeric value */
int tcl_int(tcl_value_t *v);
const char *tcl_string(tcl_value_t *v);

/* List values */
tcl_value_t *tcl_list_new();
tcl_value_t *tcl_list_append(tcl_value_t *v, tcl_value_t *tail);
tcl_value_t *tcl_list_item(tcl_value_t *v, int index);
int tcl_list_length(tcl_value_t *v);
void tcl_list_free(tcl_value_t *v);
```

Keep in mind, that `..._append()` functions free the tail argument.
Also, the string returned by `tcl_string()` it not meant to be mutated or
cached.

In the default implementation lists are implemented as raw strings that add
some escaping (braces) around each item. It's a simple solution that also
reduces the code, but in some exotic cases the escaping can become wrong and
invalid results will be returned.

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

