# ParTcl - a minimal Tcl interpreter

Note: This is a fork; see [https://github.com/zserge/partcl] for the original.

## Features

* Small, plain C99 code (although now twice as long as the ~600 lines of the original)
* No external dependencies
* Good test coverage
* Can be extended with custom Tcl commands
* Runs well on bare metal embedded MCUs

Built-in commands:

* `subst arg`
* `set var ?val?`
* `expr`
* `while cond loop`
* `if cond branch ?cond? ?branch? ?other?`
* `proc name args body`
* `return`
* `break`
* `continue`

## Usage

```c
struct tcl tcl;
const char *s = "set x 4; puts [expr 2 + $x * 10]";

tcl_init(&tcl);
if (tcl_eval(&tcl, s, strlen(s)) != FERROR) {
    printf("%.*s\n", tcl_length(tcl.result), tcl_string(tcl.result));
}
tcl_destroy(&tcl);
```

## Language syntax

Tcl script is made up of _commands_ separated by semicolons or newline
symbols. Commands in their turn are made up of _words_ separated by whitespace.
To make whitespace a part of the word one may use double quotes or braces.

An important part of the language is _command substitution_, when the result of
a command inside square braces is returned as a part of the outer command, e.g.
`puts [expr 1 + 2]`.

The only data type of the language is a string. Although it may complicate
mathematical operations, it opens a broad way for building your own DSLs to
enhance the language.

## Lexer

Any symbol can be part of the word, except for the following special symbols:

* whitespace, tab - used to delimit words
* `\r`, `\n`, semicolon or EOF (zero-terminator) - used to delimit commands
* Braces, square brackets, dollar sign - used for substitution and grouping

ParTcl has special helper functions for these char classes:

```
static int tcl_is_space(char c);
static int tcl_is_end(char c);
static int tcl_is_special(char c, int q);
```

`tcl_is_special` behaves differently depending on the quoting mode (`q`
parameter). Inside a quoted string braces, semicolon and end-of-line symbols
lose their special meaning and become regular printable characters.

ParTcl lexer is implemented in one function:

```
int tcl_next(const char *list, size_t length, const char **from, const char **to, bool *quote, bool variable);
```

`tcl_next` function finds the next token in the string `list`. Paramters `from` and `to` are
set to point to the token start/end. Parameter `quote` denotes the quoting mode and is
changed if `"` is met. Parameter `variable` is for special handling of (unquoted) variable
names and is set to `true` when `tcl_next` calls itself recursively. When calling the lexer
from your own code, `variable` should always be set to `false`.

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
tcl_value_t *tcl_list_alloc();
tcl_value_t *tcl_list_append(tcl_value_t *v, tcl_value_t *tail);
tcl_value_t *tcl_list_at(tcl_value_t *v, int index);
int tcl_list_length(tcl_value_t *v);
void tcl_list_free(tcl_value_t *v);
```

Keep in mind, that `..._append()` functions must free the tail argument.
Also, the string returned by `tcl_string()` it not meant to be mutated or
cached.

In the default implementation lists are implemented as raw strings that add
some escaping (braces) around each item. It's a simple solution that also
reduces the code, but in some exotic cases the escaping can become wrong and
invalid results will be returned.

When creating a value with `tcl_value`, the block of data to initialize the
value may be marked as "binary". For a binary block is "quoted" in a special
way, such that it may contain embedded zeroes or any other kind of bytes.
If the `data` parameter of `tcl_value` has embedded zeroes, it will automatically
by marked as binary, but the zero byte is not the only problematic character that
may occur in a binary block. Therefore, if you pass binary data to `tcl_value`,
set `binary` to `true`.

When appending values to one another with `tcl_append`, if either block is marked 
as binary, both are joined in binary mode.

## Environments

A special type, `struct tcl_env` is used to keep the evaluation environment (a
set of functions). The interpreter creates a new environment for each
user-defined procedure, also there is one global environment per interpreter.

There are only 3 functions related to the environment. One creates a new environment, 
another seeks for a variable (or creates a new one), the last one destroys the environment 
and all its variables.

These functions use malloc/free, but can easily be rewritten to use memory pools instead.

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

## Builtin commands

"set" - `tcl_cmd_set`, assigns value to the variable (if any) and returns the
current variable value.

"subst" - `tcl_cmd_subst`, does command substitution in the argument string.

"puts" - `tcl_cmd_puts`, prints argument to the stdout, followed by a newline.
This command can be disabled using `#define TCL_DISABLE_PUTS`, which is handy
for embedded systems that don't have "stdout".

"proc" - `tcl_cmd_proc`, creates a new command appending it to the list of
current interpreter commands. That's how user-defined commands are built.

"if" - `tcl_cmd_if`, does a simple `if {cond} {then} {cond2} {then2} {else}`.

"while" - `tcl_cmd_while`, runs a while loop `while {cond} {body}`. One may use
"break", "continue" or "return" inside the loop to contol the flow.

"expr" - `tcl_cmd_expr` interprets the infix expression that follows. This is
and integer-only expression parser, but supporting most of the Tcl operator set
(`in` and `ni` are currently missing), with the same precedence levels as the
official Tcl. The expression parser takes nearly half the size of ParTcl, and
thus it can be disabled to save space (`#define TCL_DISABLE_MATH`).

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


