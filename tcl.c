/*
The MIT License (MIT)

Copyright (c) 2016 Serge Zaitsev

Nota Bene: this is a fork of the original version by Thiadmer Riemersma, with
many changes.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcl.h"

#if defined WIN32 || defined _WIN32
# if defined __MINGW32__ || defined __MINGW64__ || defined _MSC_VER
    size_t strlcat(char *dst, const char *src, size_t size);
    size_t strlcpy(char *dst, const char *src, size_t size);
# endif
#elif defined __linux__
# include <bsd/string.h>
#endif

#if defined FORTIFY
# include "fortify.h"	/* malloc tracking & debugging library */
#endif

#define MAX_VAR_LENGTH  256

struct tcl_value {
  char *data;
  size_t length;  /**< size of the valid data */
  size_t size;    /**< size of the memory buffer that was allocated */
};

/* Token type and control flow constants */
enum { TERROR, TEXECPOINT, TFIELD, TPART, TDONE };
enum { FNORMAL, FERROR, FRETURN, FBREAK, FCONT, FEXIT };

#define ISERROR(f)      (((f) & 0xff) == FERROR)

/* Lexer flags & options */
#define LEX_QUOTE   0x01  /* inside a double-quote section */
#define LEX_VAR     0x02  /* special mode for parsing variable names */
#define LEX_NO_CMT  0x04  /* don't allow comment here (so comment is allowed when this is not set) */

/* special character classification */
#define CTYPE_OPERATOR  0x01
#define CTYPE_SPACE     0x02
#define CTYPE_TERM      0x04
#define CTYPE_SPECIAL   0x08
#define CTYPE_Q_SPECIAL 0x10
#define CTYPE_ALPHA     0x20
#define CTYPE_DIGIT     0x40
#define CTYPE_HEXDIGIT  0x80

static unsigned char ctype_table[256] = { 0 };
static void init_ctype(void) {
  if (!ctype_table[0]) {
    memset(ctype_table, 0, sizeof(ctype_table));
    for (unsigned c = 0; c < 256; c++) {
      /* operator */
      if (c == '|' || c == '&' || c == '~' || c == '<' || c == '>' ||
          c == '=' || c == '!' || c == '-' || c == '+' || c == '*' ||
          c == '/' || c == '%' || c == '?' || c == ':') {
        ctype_table[c] |= CTYPE_OPERATOR;
      }
      /* space */
      if (c == ' ' || c == '\t') {
        ctype_table[c] |= CTYPE_SPACE;
      }
      /* terminator (execution point) */
      if (c == '\n' || c == '\r' || c == ';' || c == '\0') {
        ctype_table[c] |= CTYPE_TERM;
      }
      /* special: always */
      if (c == '[' || c == ']' || c == '"' || c == '\\' || c == '\0' || c == '$') {
        ctype_table[c] |= CTYPE_SPECIAL;
      }
      /* special: if outside double quotes */
      if (c == '{' || c == '}' || c == ';' || c == '\r' || c == '\n') {
        ctype_table[c] |= CTYPE_Q_SPECIAL;
      }
      /* digits (decimal digits are also hexadecimal) */
      if (c >= '0' && c <= '9') {
        ctype_table[c] |= CTYPE_DIGIT | CTYPE_HEXDIGIT;
      }
      /* other hexadecimal digits */
      if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        ctype_table[c] |= CTYPE_HEXDIGIT;
      }
      /* alphabetic characters (ASCII only) */
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        ctype_table[c] |= CTYPE_ALPHA;
      }
    }
  }
}
#define tcl_is_operator(c)  ((ctype_table[(unsigned char)(c)] & CTYPE_OPERATOR) != 0)
#define tcl_is_space(c)     ((ctype_table[(unsigned char)(c)] & CTYPE_SPACE) != 0)
#define tcl_is_end(c)       ((ctype_table[(unsigned char)(c)] & CTYPE_TERM) != 0)
#define tcl_is_special(c,quote) \
        ((ctype_table[(unsigned char)(c)] & CTYPE_SPECIAL) != 0 ||  \
         (!quote && (ctype_table[(unsigned char)(c)] & CTYPE_Q_SPECIAL) != 0))
#define tcl_isalpha(c)      ((ctype_table[(unsigned char)(c)] & CTYPE_ALPHA) != 0)
#define tcl_isdigit(c)      ((ctype_table[(unsigned char)(c)] & CTYPE_DIGIT) != 0)
#define tcl_isxdigit(c)     ((ctype_table[(unsigned char)(c)] & CTYPE_HEXDIGIT) != 0)

static int tcl_next(const char *string, size_t length, const char **from, const char **to,
                    unsigned *flags) {
  unsigned int i = 0;
  int depth = 0;
  bool quote = ((*flags & LEX_QUOTE) != 0);

  /* Skip leading spaces if not quoted */
  for (; !quote && length > 0 && tcl_is_space(*string); string++, length--)
    {}
  if (length == 0) {
    *from = *to = string;
    return TDONE;
  }
  /* Skip comment (then skip leading spaces again */
  if (*string == '#' && !(*flags & LEX_NO_CMT)) {
    assert(!quote); /* this flag cannot be set, if the "no-comment" flag is set */
    for (; length > 0 && *string != '\n' && *string != '\r'; string++, length--)
      {}
    for (; length > 0 && tcl_is_space(*string); string++, length--)
      {}
  }
  *flags |= LEX_NO_CMT;

  *from = string;
  /* Terminate command if not quoted */
  if (!quote && length > 0 && tcl_is_end(*string)) {
    *to = string + 1;
    *flags &= ~LEX_NO_CMT;  /* allow comment at this point */
    return TEXECPOINT;
  }

  if (*string == '$') { /* Variable token, must not start with a space or quote */
    int deref = 1;
    while (string[deref] == '$' && !(*flags & LEX_VAR)) {  /* double deref */
      deref++;
    }
    if (tcl_is_space(string[deref]) || string[deref] == '"' || (*flags & LEX_VAR)) {
      return TERROR;
    }
    unsigned saved_flags = *flags;
    *flags = (*flags & ~LEX_QUOTE) | LEX_VAR; /* quoting is off, variable name parsing is on */
    int r = tcl_next(string + deref, length - deref, to, to, flags);
    *flags = saved_flags;
    return (r == TFIELD && quote) ? TPART : r;
  }

  if (*string == '[' || (!quote && *string == '{')) {
    /* Interleaving pairs are not welcome, but it simplifies the code */
    char open = *string;
    char close = (open == '[' ? ']' : '}');
    for (i = 1, depth = 1; i < length && depth != 0; i++) {
      if (string[i] == '\\' && i+1 < length && (string[i+1] == open || string[i+1] == close)) {
        i++;  /* escaped brace/bracket, skip both '\' and the character that follows it */
      } else if (string[i] == open) {
        depth++;
      } else if (string[i] == close) {
        depth--;
      }
    }
  } else if (*string == '"') {
    *flags ^= LEX_QUOTE;                  /* toggle flag */
    quote = ((*flags & LEX_QUOTE) != 0);  /* update local variable to match */
    *from = *to = string + 1;
    if (quote) {
      return TPART;
    }
    if (length < 2 || (!tcl_is_space(string[1]) && !tcl_is_end(string[1]))) {
      return TERROR;
    }
    *from = *to = string + 1;
    return TFIELD;
  } else if (*string == ']' || *string == '}') {
    return TERROR;    /* Unbalanced bracket or brace */
  } else if (*string == '\\') {
    i = (length >= 4 && *(string + 1) == 'x') ? 4 : 2;
  } else {
    bool isvar = ((*flags & LEX_VAR) != 0);
    bool array_close = false;
    while (i < length && !array_close &&              /* run until string completed... */
           (quote || !tcl_is_space(string[i])) &&     /* ... and no whitespace (unless quoted) ... */
           !(isvar && tcl_is_operator(string[i])) &&  /* ... and no operator in variable mode ... */
           !tcl_is_special(string[i], quote)) {       /* ... and no special characters (where "special" depends on quote status) */
      if (string[i] == '(' && !quote && isvar) {
        for (i = 1, depth = 0; i < length; i++) {
          if (string[i] == '\\' && i+1 < length && (string[i+1] == '(' || string[i+1] == ')')) {
            i++;  /* escaped brace/bracket, skip both '\' and the character that follows it */
          } else if (string[i] == '(') {
            depth++;
          } else if (string[i] == ')') {
            if (--depth == 0)
              break;
          }
        }
        if (string[i] == ')') {
          array_close = true;
        } else {
          i--;
        }
      } else if (string[i] == ')' && !quote && isvar) {
        break;
      }
      i++;
    }
  }
  *to = string + i;
  if (i > length || (i == length && depth)) {
    return TERROR;
  }
  if (quote) {
    return TPART;
  }
  return (tcl_is_space(string[i]) || tcl_is_end(string[i])) ? TFIELD : TPART;
}

/* A helper parser struct and macro (requires C99) */
struct tcl_parser {
  const char *from;
  const char *to;
  const char *start;
  const char *end;
  unsigned flags;
  int token;
};
static struct tcl_parser init_tcl_parser(const char *start, const char *end, int token) {
  struct tcl_parser p;
  memset(&p, 0, sizeof(p));
  p.start = start;
  p.end = end;
  p.token = token;
  return p;
}
#define tcl_each(s, len, skiperr)                                              \
  for (struct tcl_parser p = init_tcl_parser((s), (s) + (len), TERROR);        \
       p.start < p.end &&                                                      \
       (((p.token = tcl_next(p.start, p.end - p.start, &p.from, &p.to,         \
                             &p.flags)) != TERROR) ||                          \
        (skiperr));                                                            \
       p.start = p.to)

/* -------------------------------------------------------------------------- */

bool tcl_isnumber(const struct tcl_value *value) {
  if (!value) {
    return false;
  }
  const char *p = value->data;
  while (tcl_is_space(*p)) { p++; }     /* allow leading whitespace */
  if (*p == '-') { p++; }               /* allow minus sign before the number */
  if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X') ) {
    p += 2;
    while (tcl_isxdigit(*p)) { p++; }   /* hexadecimal number */
  } else if (*p == '0') {
    p++;                                /* octal number */
    while ('0' <= *p && *p <= '7') { p++; }
  } else {
    while (tcl_isdigit(*p)) { p++; }    /* decimal number */
  }
  while (tcl_is_space(*p)) { p++; }     /* allow trailing whitespace */
  return (*p == '\0');                  /* if dropped on EOS -> successfully
                                           parsed an integer format */
}

const char *tcl_data(const struct tcl_value *value) {
  return value ? value->data : NULL;
}

size_t tcl_length(const struct tcl_value *value) {
  return value ? value->length : 0;
}

tcl_int tcl_number(const struct tcl_value *value) {
  if (tcl_isnumber(value)) {
    return strtoll(value->data, NULL, 0);
  }
  return 0;
}

struct tcl_value *tcl_free(struct tcl_value *value) {
  assert(value && value->data);
  free(value->data);
  free(value);
  return NULL;
}

bool tcl_append(struct tcl_value *value, struct tcl_value *tail) {
  assert(value);
  assert(tail);
  if (tcl_length(tail) == 0) {
    tcl_free(tail);     /* no new data to append, done quickly */
    return true;
  }
  size_t needed = tcl_length(value) + tcl_length(tail) + 1;  /* allocate 1 byte extra for EOS */
  if (value->size < needed) {
    size_t newsize = value->size * 2;
    while (newsize < needed) {
      newsize *= 2;
    }
    char *b = malloc(newsize);
    if (b) {
      if (tcl_length(value) > 0) {
        memcpy(b, tcl_data(value), tcl_length(value));
      }
      free(value->data);
      value->data = b;
      value->size = newsize;
    }
  }
  if (value->size >= needed) {
    memcpy(value->data + tcl_length(value), tcl_data(tail), tcl_length(tail));
    value->length = tcl_length(value) + tcl_length(tail);
    value->data[value->length] = '\0';
  }
  tcl_free(tail);
  return (value->size >= needed);
}

struct tcl_value *tcl_value(const char *data, size_t len) {
  struct tcl_value *value = malloc(sizeof(struct tcl_value));
  if (value) {
    size_t size = 8;
    while (size < len + 1) {
      size *= 2;
    }
    value->data = malloc(size);
    if (value->data) {
      memcpy(value->data, data, len);
      value->data[len] = '\0';  /* set EOS */
      value->length = len;
      value->size = size;
    } else {
      free(value);
      value = NULL;
    }
  }
  return value;
}

static struct tcl_value *tcl_dup(const struct tcl_value *value) {
  assert(value);
  return tcl_value(tcl_data(value), tcl_length(value));
}

struct tcl_value *tcl_list_new(void) {
  return tcl_value("", 0);
}

int tcl_list_length(const struct tcl_value *list) {  /* returns the number of items in the list */
  int count = 0;
  tcl_each(tcl_data(list), tcl_length(list) + 1, 0) {
    if (p.token == TFIELD) {
      count++;
    }
  }
  return count;
}

static bool tcl_list_item_ptr(const struct tcl_value *list, int index, const char **data, size_t *size) {
  int i = 0;
  tcl_each(tcl_data(list), tcl_length(list) + 1, 0) {
    if (p.token == TFIELD) {
      if (i == index) {
        *data = p.from;
        *size = p.to - p.from;
        if (**data == '{') {
          *data += 1;
          *size -= 2;
        }
        return true;
      }
      i++;
    }
  }
  return false;
}

struct tcl_value *tcl_list_item(struct tcl_value *list, int index) {
  const char *data;
  size_t sz;
  if (tcl_list_item_ptr(list, index, &data, &sz))
    return tcl_value(data, sz);
  return NULL;
}

bool tcl_list_append(struct tcl_value *list, struct tcl_value *tail) {
  /* calculate required memory */
  assert(list);
  assert(tail);
  bool separator = (tcl_length(list) > 0);
  size_t extrasz = separator ? 1 : 0;
  bool quote = false;
  if (tcl_length(tail) > 0) {
    const char *p = tcl_data(tail);
    for (int i = 0; i < tcl_length(tail) && !quote; i++) {
      if (tcl_is_space(p[i]) || tcl_is_special(p[i], false)) {
        quote = true;
      }
    }
  } else {
    quote = true; /* quote, to create an empty element */
  }
  if (quote) {
    extrasz += 2;
  }
  /* allocate & copy */
  size_t needed = tcl_length(list) + tcl_length(tail) + extrasz + 1;
  if (list->size < needed) {
    size_t newsize = list->size * 2;
    while (newsize < needed) {
      newsize *= 2;
    }
    char *newbuf = malloc(newsize);
    if (!newbuf) {
      tcl_free(tail);
      return false;
    }
    memcpy(newbuf, tcl_data(list), tcl_length(list));
    free(list->data);
    list->data = newbuf;
    list->size = newsize;
  }
  char *tgt = (char*)tcl_data(list) + tcl_length(list);
  if (separator) {
    memcpy(tgt, " ", 1);
    tgt += 1;
  }
  if (quote) {
    memcpy(tgt, "{", 1);
    tgt += 1;
  }
  if (tcl_length(tail) > 0) {
    memcpy(tgt, tcl_data(tail), tcl_length(tail));
    tgt += tcl_length(tail);
  }
  if (quote) {
    memcpy(tgt, "}", 1);
    tgt += 1;
  }
  *tgt = '\0';
  list->length = tcl_length(list) + tcl_length(tail) + extrasz;
  tcl_free(tail);
  return true;
}

/* -------------------------------------------------------------------------- */

enum {
  TCLERR_UNKNOWN,     /**< no known error, or no error was flagged */
  TCLERR_GENERAL,     /**< unspecified error */
  TCLERR_MEMORY,      /**< memory allocation error */
  TCLERR_SYNTAX,      /**< general syntax error */
  TCLERR_BRACES,      /**< unbalanced curly braces */
  TCLERR_EXPR,        /**< error in expression */
  TCLERR_CMDUNKNOWN,  /**< unknown command */
  TCLERR_CMDARGCOUNT, /**< wrong argument count on command */
  TCLERR_SUBCMD,      /**< unsupported subcommand */
  TCLERR_VARUNKNOWN,  /**< unknown variable name */
  TCLERR_NAMEINVALID, /**< invalid symbol name */
  TCLERR_NAMEEXISTS,  /**< symbol name already exists */
  TCLERR_ARGUMENT,    /**< incorrect (or missing) argument to a command */
  TCLERR_DEFAULTVAL,  /**< incorrect default value on parameter */
  TCLERR_SCOPE,       /**< scope error (e.g. command is allowed in local scope only) */
  TCLERR_FILEIO,      /**< operation on file failed (e.g. file not found) */
  TCLERR_USER,        /**< error set with the "error" command */
};

static char *tcl_int2string(char *buffer, size_t bufsz, int radix, tcl_int value);
static int tcl_error_result(struct tcl *tcl, int code, const char *info);
static int tcl_var_index(const char *name, size_t *baselength);

struct tcl_cmd {
  struct tcl_value *name; /**< function name */
  unsigned short minargs; /**< minimum number of parameters (including function name) */
  unsigned short maxargs; /**< maximum number of parameters, USHRT_MAX = no maximum */
  tcl_cmd_fn_t fn;        /**< function pointer */
  void *user;             /**< user value, used for the code block for Tcl procs */
  const char *declpos;    /**< position of declaration (Tcl procs) */
  struct tcl_cmd *next;
};

struct tcl_errinfo {
  const char *codebase;   /**< the string with the main block of a proc or of the script */
  size_t codesize;        /**< the size of the main plock */
  const char *currentpos; /**< points to the start of the current command */
};

struct tcl_env {
  struct tcl_var *vars;
  struct tcl_env *parent;
  struct tcl_errinfo errinfo;
};

struct tcl_var {
  struct tcl_value *name;
  struct tcl_value **value; /**< array of values */
  int elements;           /**< for an array, the number of "values" allocated */
  struct tcl_env *env;    /**< if set, this variable is an alias for a variable at a different scope */
  struct tcl_value *alias;/**< if set, the variable name this variable is aliased to */
  struct tcl_var *next;
};

static struct tcl_env *tcl_env_alloc(struct tcl_env *parent) {
  struct tcl_env *env = malloc(sizeof(struct tcl_env));
  memset(env, 0, sizeof(struct tcl_env));
  env->parent = parent;
  return env;
}

static struct tcl_var *tcl_env_var(struct tcl_env *env, const char *name) {
  struct tcl_var *var = malloc(sizeof(struct tcl_var));
  if (var) {
    memset(var, 0, sizeof(struct tcl_var));
    assert(name);
    size_t namesz;
    tcl_var_index(name, &namesz);
    var->name = tcl_value(name, namesz);
    var->elements = 1;
    var->value = malloc(var->elements * sizeof(struct tcl_value*));
    if (var->value) {
      var->value[0] = tcl_value("", 0);
      var->next = env->vars;
      env->vars = var;
    } else {
      free(var);
      var = NULL;
    }
  }
  return var;
}

static void tcl_var_free_values(struct tcl_var *var) {
  assert(var && var->value);
  for (int idx = 0; idx < var->elements; idx++) {
    if (var->value[idx]) {
      tcl_free(var->value[idx]);
    }
  }
  free(var->value);
}

static struct tcl_env *tcl_env_free(struct tcl_env *env) {
  struct tcl_env *parent = env->parent;
  while (env->vars) {
    struct tcl_var *var = env->vars;
    env->vars = env->vars->next;
    tcl_free(var->name);
    tcl_var_free_values(var);
    if (var->alias) {
      tcl_free(var->alias);
    }
    free(var);
  }
  free(env);
  return parent;
}

int tcl_cur_scope(struct tcl *tcl) {
  struct tcl_env *global_env = tcl->env;
  int n = 0;
  while (global_env->parent) {
    global_env = global_env->parent;
    n++;
  }
  return n;
}

static struct tcl_env *tcl_env_scope(struct tcl *tcl, int level) {
  assert(level >= 0 && level <= tcl_cur_scope(tcl));
  level = tcl_cur_scope(tcl) - level; /* from absolute to relative level */
  struct tcl_env *env = tcl->env;
  while (level-- > 0) {
    env = env->parent;
  }
  assert(env);
  return env;
}

static const char *tcl_alias_name(const struct tcl_var *var) {
  assert(var);
  assert(var->env);     /* should only call this function on aliased variables */
  return tcl_data(var->alias ? var->alias : var->name);
}

static int tcl_var_index(const char *name, size_t *baselength) {
  size_t len = strlen(name);
  const char *ptr = name + len;
  int idx = 0;
  if (ptr > name && *(ptr - 1) == ')') {
    ptr--;
    while (ptr > name && tcl_isdigit(*(ptr - 1))) {
      ptr--;
    }
    if (ptr > name + 1 && *(ptr - 1) == '(') {
      idx = (int)strtol(ptr, NULL, 10);
      if (idx >= 0) {
        len = ptr - name - 1;
      }
    }
  }
  if (baselength) {
    *baselength = len;
  }
  return idx;
}

static struct tcl_var *tcl_findvar(struct tcl_env *env, const char *name) {
  struct tcl_var *var;
  size_t namesz;
  tcl_var_index(name, &namesz);
  for (var = env->vars; var != NULL; var = var->next) {
    const char *varptr = tcl_data(var->name);
    size_t varsz;
    tcl_var_index(tcl_data(var->name), &varsz);
    if (varsz == namesz && strncmp(varptr, name, varsz) == 0) {
      return var;
    }
  }
  return NULL;
}

struct tcl_value *tcl_var(struct tcl *tcl, const char *name, struct tcl_value *value) {
  struct tcl_var *var = tcl_findvar(tcl->env, name);
  if (var && var->env) { /* found local alias of a global/upvar variable; find the global/upvar */
    var = tcl_findvar(var->env, tcl_alias_name(var));
  }
  if (!var) {
    if (!value) {
      /* value being read before being set */
      tcl_error_result(tcl, TCLERR_VARUNKNOWN, name);
      return NULL;
    }
    /* create new variable */
    var = tcl_env_var(tcl->env, name);
  }
  int idx = tcl_var_index(name, NULL);
  if (var->elements <= idx) {
    size_t newsize = var->elements;
    while (newsize <= idx) {
      newsize *= 2;
    }
    struct tcl_value **newlist = malloc(newsize * sizeof(struct tcl_value*));
    if (newlist) {
      memset(newlist, 0, newsize * sizeof(struct tcl_value*));
      memcpy(newlist, var->value, var->elements * sizeof(struct tcl_value*));
      free(var->value);
      var->value = newlist;
      var->elements = newsize;
    } else {
      tcl_error_result(tcl, TCLERR_MEMORY, NULL);
      idx = 0;  /* sets/returns wrong index, but avoid accessing out of range index */
    }
  }
  if (value) {
    if (var->value[idx]) {
      tcl_free(var->value[idx]);
    }
    var->value[idx] = value;
  } else if (var->value[idx] == NULL) {
    var->value[idx] = tcl_value("", 0);
  }
  return var->value[idx];
}

static void tcl_var_free(struct tcl_env *env, struct tcl_var *var) {
  /* unlink from list */
  if (env->vars == var) {
    env->vars = var->next;
  } else {
    struct tcl_var *pred = env->vars;
    while (pred->next && pred->next != var) {
      pred = pred->next;
    }
    if (pred->next == var) {
      pred->next = var->next;
    }
  }
  /* then delete */
  tcl_free(var->name);
  tcl_var_free_values(var);
  if (var->alias) {
    tcl_free(var->alias);
  }
  free(var);
}

int tcl_result(struct tcl *tcl, int flow, struct tcl_value *result) {
  assert(tcl && tcl->result);
  tcl_free(tcl->result);
  tcl->result = result;
  return flow;
}

static int tcl_numeric_result(struct tcl *tcl, int flow, tcl_int result) {
  char buf[64] = "";
  const char *ptr = tcl_int2string(buf, sizeof(buf), 10, result);
  return tcl_result(tcl, flow, tcl_value(ptr, strlen(ptr)));
}

static int tcl_error_result(struct tcl *tcl, int code, const char *info) {
  /* check errorCode not already set, register only the first error */
  struct tcl_env *global_env = tcl_env_scope(tcl, 0);
  const struct tcl_var *glbvar = tcl_findvar(global_env, "errorCode");
  if (!glbvar) {
    struct tcl_env *save_env = tcl->env;
    tcl->env = global_env;
    char buf[64] = "";
    const char *ptr = tcl_int2string(buf, sizeof(buf), 10, code);
    tcl_var(tcl, "errorCode", tcl_value(ptr, strlen(ptr)));
    if (info) {
      tcl_var(tcl, "errorInfo", tcl_value(info, strlen(info)));
    } else {
      tcl_var(tcl, "errorInfo", tcl_value("", 0));
    }
    tcl->env = save_env;
  }
  /* make sure the error variables can be accessed locally */
  if (tcl->env != global_env) {
    tcl_var(tcl, "errorCode", tcl_value("", 0));  /* make empty local... */
    struct tcl_var *lclvar = tcl_findvar(tcl->env, "errorCode");
    assert(lclvar);
    lclvar->env = global_env;                     /* ... link to global */
    tcl_var(tcl, "errorInfo", tcl_value("", 0));
    lclvar = tcl_findvar(tcl->env, "errorInfo");
    assert(lclvar);
    lclvar->env = global_env;
  }
  return (tcl_result(tcl, FERROR, tcl_value("", 0)));
}

static int tcl_empty_result(struct tcl *tcl) {
  assert(tcl && tcl->result);
  if (tcl_length(tcl->result) > 0) {
    tcl_result(tcl, FNORMAL, tcl_value("", 0)); /* skip setting empty result if
                                                   the result is already empty */
  }
  return FNORMAL;
}

static int tcl_hexdigit(char c) {
  if ('0' <= c && c <= '9') return c - '0';
  if ('A' <= c && c <= 'F') return c - 'A' + 10;
  if ('a' <= c && c <= 'f') return c - 'a' + 10;
  return 0;
}

static int tcl_subst(struct tcl *tcl, const char *string, size_t len) {
  if (len == 0) {
    return tcl_empty_result(tcl);
  }
  switch (string[0]) {
  case '{':
    if (len < 2 || *(string + len - 1) != '}') {
      return tcl_error_result(tcl, TCLERR_BRACES, NULL);
    }
    return tcl_result(tcl, FNORMAL, tcl_value(string + 1, len - 2));
  case '$': {
    if (len >= MAX_VAR_LENGTH) {
      return tcl_error_result(tcl, TCLERR_NAMEINVALID, string + 1);
    }
    string += 1; len -= 1;      /* skip '$' */
    if (*string == '$') {
      int r = tcl_subst(tcl, string, len);
      if (r != FNORMAL) {
        return r;
      }
      string = tcl_data(tcl->result);
      len = tcl_length(tcl->result);
    }
    if (*string == '{' && len > 1 && string[len - 1] == '}') {
      string += 1; len -= 2;    /* remove one layer of braces */
    } else if (*string == '[' && len > 1 && string[len - 1] == ']') {
      struct tcl_value *expr = tcl_value(string + 1, len - 2);
      int r = tcl_eval(tcl, tcl_data(expr), tcl_length(expr) + 1);
      tcl_free(expr);
      if (r != FNORMAL) {
        return r;
      }
      string = tcl_data(tcl->result);
      len = tcl_length(tcl->result);
    }
    struct tcl_value *name = tcl_value(string, len);
    /* check for a variable index (arrays) */
    const char *start;
    for (start = tcl_data(name); *start != '\0' && *start != '('; start++)
      {}
    if (*start == '(') {
      start++;
      bool is_var = false;
      int depth = 1;
      const char *end = start;
      while (*end != '\0') {
        if (*end == ')') {
          if (--depth == 0) {
            break;
          }
        } else if (*end == '(') {
          depth++;
        } else if (*end == '$' && depth == 1) {
          is_var = true;
        }
        end++;
      }
      if (*end == ')' && is_var) {  /* evaluate index, build new name */
        int baselen = start - tcl_data(name);
        tcl_subst(tcl, start, end - start);
        tcl_free(name);
        name = tcl_value(string, baselen);  /* includes opening '(' */
        tcl_append(name, tcl_dup(tcl->result));
        tcl_append(name, tcl_value(")", 1));
      }
    }
    struct tcl_value *v = tcl_var(tcl, tcl_data(name), NULL);
    tcl_free(name);
    return v ? tcl_result(tcl, FNORMAL, tcl_dup(v)) : tcl_error_result(tcl, TCLERR_VARUNKNOWN, NULL);
  }
  case '[': {
    struct tcl_value *expr = tcl_value(string + 1, len - 2);
    int r = tcl_eval(tcl, tcl_data(expr), tcl_length(expr) + 1);
    tcl_free(expr);
    return r;
  }
  case '\\': {
    if (len <= 1) {
      return tcl_error_result(tcl, TCLERR_SYNTAX, NULL);
    }
    char buf[] = "*";
    switch (*(string + 1)) {
    case 'n':
      buf[0] = '\n';
      break;
    case 'r':
      buf[0] = '\r';
      break;
    case 't':
      buf[0] = '\t';
      break;
    case '\n':
      buf[0] = ' ';
      break;
    case 'x':
      if (len >= 4) {
        buf[0] = (char)(tcl_hexdigit(string[2]) << 4 | tcl_hexdigit(string[3]));
      }
      break;
    default:
      buf[0] = *(string + 1);
    }
    return (tcl_result(tcl, FNORMAL, tcl_value(buf, 1)));
  }
  default:
    return tcl_result(tcl, FNORMAL, tcl_value(string, len));
  }
}

static struct tcl_cmd *tcl_lookup_cmd(struct tcl *tcl, struct tcl_value *name) {
  assert(name);
  for (struct tcl_cmd *cmd = tcl->cmds; cmd != NULL; cmd = cmd->next) {
    if (strcmp(tcl_data(name), tcl_data(cmd->name)) == 0) {
      return cmd;
    }
  }
  return NULL;
}

static int tcl_exec_cmd(struct tcl *tcl, struct tcl_value *list) {
  struct tcl_value *cmdname = tcl_list_item(list, 0);
  struct tcl_cmd *cmd = tcl_lookup_cmd(tcl, cmdname);
  int r;
  if (cmd) {
    unsigned numargs = tcl_list_length(list);
    if (cmd->minargs <= numargs && numargs <= cmd->maxargs)
      r = cmd->fn(tcl, list, cmd->user);
    else
      r = tcl_error_result(tcl, TCLERR_CMDARGCOUNT, tcl_data(cmdname));
  } else {
    r = tcl_error_result(tcl, TCLERR_CMDUNKNOWN, tcl_data(cmdname));
  }
  tcl_free(cmdname);
  return r;
}

int tcl_eval(struct tcl *tcl, const char *string, size_t length) {
  if (!tcl->env->errinfo.codebase) {
    tcl->env->errinfo.codebase = string;
    tcl->env->errinfo.codesize = length;
  }
  struct tcl_value *list = tcl_list_new();
  struct tcl_value *cur = NULL;
  int result = tcl_empty_result(tcl);  /* preset to empty result */
  bool markposition = true;
  tcl_each(string, length, 1) {
    if (markposition) {
      struct tcl_errinfo *info = &tcl->env->errinfo;
      if (p.from >= info->codebase && p.from < info->codebase + info->codesize) {
        info->currentpos = p.from;
      }
      markposition = false;
    }
    switch (p.token) {
    case TERROR:
      result = tcl_error_result(tcl, TCLERR_SYNTAX, NULL);
      break;
    case TFIELD:
      result = tcl_subst(tcl, p.from, p.to - p.from);
      if (cur) {
        tcl_append(cur, tcl_dup(tcl->result));
      } else {
        cur = tcl_dup(tcl->result);
      }
      tcl_list_append(list, cur);
      cur = NULL;
      break;
    case TPART:
      result = tcl_subst(tcl, p.from, p.to - p.from);
      struct tcl_value *part = tcl_dup(tcl->result);
      if (cur) {
        tcl_append(cur, part);
      } else {
        cur = part;
      }
      break;
    case TEXECPOINT:
    case TDONE:
      if (tcl_list_length(list) > 0) {
        result = tcl_exec_cmd(tcl, list);
        tcl_free(list);
        list = tcl_list_new();
      } else {
        result = FNORMAL;
      }
      markposition = true;
      break;
    }
    if (result != FNORMAL) {
      break;  /* error information already set */
    }
  }
  /* when arrived at the end of the buffer, if the list is non-empty, run that
     last command */
  if (result == FNORMAL && tcl_list_length(list) > 0) {
    if (cur) {
      tcl_list_append(list, cur);
      cur = NULL;
    }
    result = tcl_exec_cmd(tcl, list);
  }
  tcl_free(list);
  if (cur) {
    tcl_free(cur);
  }
  return result;
}

/* -------------------------------------------------------------------------- */

static int tcl_expression(struct tcl *tcl, const char *expression, tcl_int *result); /* forward declaration */

struct tcl_cmd *tcl_register(struct tcl *tcl, const char *name, tcl_cmd_fn_t fn,
                             unsigned short minargs, unsigned short maxargs,
                             void *user) {
  struct tcl_cmd *cmd = malloc(sizeof(struct tcl_cmd));
  if (cmd) {
    memset(cmd, 0, sizeof(struct tcl_cmd));
    cmd->name = tcl_value(name, strlen(name));
    cmd->fn = fn;
    cmd->user = user;
    cmd->minargs = minargs;
    cmd->maxargs = (maxargs == 0) ? USHRT_MAX : maxargs;
    cmd->next = tcl->cmds;
    tcl->cmds = cmd;
  }
  return cmd;
}

static int tcl_cmd_set(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *name = tcl_list_item(args, 1);
  assert(name);
  struct tcl_value *val = tcl_list_item(args, 2);
  val = tcl_var(tcl, tcl_data(name), val);
  tcl_free(name);
  return val ? tcl_result(tcl, FNORMAL, tcl_dup(val)) : tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
}

static int tcl_cmd_unset(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    struct tcl_value *name = tcl_list_item(args, 1);
    assert(name);
    struct tcl_var *var = tcl_findvar(tcl->env, tcl_data(name));
    if (var) {
      if (var->env) {
        struct tcl_var *ref_var = tcl_findvar(var->env, tcl_alias_name(var));
        tcl_var_free(var->env, ref_var);
      }
      tcl_var_free(tcl->env, var);
    }
    tcl_free(name);
  }
  return tcl_empty_result(tcl);
}

static int tcl_cmd_global(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  if (!tcl->env->parent) {
    return tcl_error_result(tcl, TCLERR_SCOPE, NULL);
  }
  int r = FNORMAL;
  int n = tcl_list_length(args);
  for (int i = 1; i < n && r == FNORMAL; i++) {
    struct tcl_value *name = tcl_list_item(args, i);
    assert(name);
    if (tcl_findvar(tcl->env, tcl_data(name)) != NULL) {
      /* name exists locally, cannot create an alias with the same name */
      r = tcl_error_result(tcl, TCLERR_NAMEEXISTS, tcl_data(name));
    } else {
      struct tcl_env *global_env = tcl_env_scope(tcl, 0);
      if (tcl_findvar(global_env, tcl_data(name)) == NULL) {
        /* name not known as a global, create it first */
        struct tcl_env *save_env = tcl->env;
        tcl->env = global_env;
        tcl_var(tcl, tcl_data(name), tcl_value("", 0));
        tcl->env = save_env;
      }
      /* make local, find it back, mark it as an alias for a global */
      tcl_var(tcl, tcl_data(name), tcl_value("", 0));  /* make local */
      struct tcl_var *var = tcl_findvar(tcl->env, tcl_data(name));
      if (var) {
        var->env = global_env; /* mark as an alias to the global */
      }
    }
    tcl_free(name);
  }
  return r;
}

static int tcl_cmd_upvar(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FNORMAL;
  int numargs = tcl_list_length(args);
  int i = 1;
  /* get desired level (which is optional) */
  int level;
  struct tcl_value *v = tcl_list_item(args, i);
  assert(v);
  const char *ptr = tcl_data(v);
  if (isdigit(*ptr) || (*ptr == '-' && isdigit(*(ptr + 1))) || (*ptr == '#' && isdigit(*(ptr + 1)))) {
    if (*ptr == '#') {
      level = (int)strtol(ptr + 1, NULL, 10);
    } else {
      level = (int)strtol(ptr, NULL, 10);
      if (level < 0) {
        level = 0;
      }
      level = tcl_cur_scope(tcl) - level;   /* make absolute level (from relative) */
    }
    i++;
  } else {
    level = tcl_cur_scope(tcl) - 1;         /* move up one level */
  }
  tcl_free(v);
  if (level < 0 || level > tcl_cur_scope(tcl)) {
    return tcl_error_result(tcl, TCLERR_SCOPE, NULL);
  }
  struct tcl_env *ref_env = tcl_env_scope(tcl, level);
  assert(ref_env);
  /* go through all variable pairs */
  while (i + 1 < numargs && r == FNORMAL) {
    struct tcl_value *name = tcl_list_item(args, i);
    assert(name);
    struct tcl_value *alias = tcl_list_item(args, i + 1);
    assert(alias);
    if (tcl_findvar(tcl->env, tcl_data(alias)) != NULL) {
      /* name for the alias already exists (as a local variable) */
      r = tcl_error_result(tcl, TCLERR_NAMEEXISTS, tcl_data(alias));
    } else if (tcl_findvar(ref_env, tcl_data(name)) == NULL) {
      /* reference variable does not exist (at the indicated scope) */
      r = tcl_error_result(tcl, TCLERR_VARUNKNOWN, tcl_data(name));
    } else {
      /* make local, find it back, mark it as an alias for a global */
      tcl_var(tcl, tcl_data(alias), tcl_value("", 0));  /* make local */
      struct tcl_var *var = tcl_findvar(tcl->env, tcl_data(alias));
      if (var) {
        var->env = ref_env; /* mark as an alias to the upvar */
        var->alias = tcl_dup(name);
      }
    }
    tcl_free(name);
    tcl_free(alias);
    i += 2;
  }
  if (i < numargs) {
    r = tcl_error_result(tcl, TCLERR_CMDARGCOUNT, "upvar"); /* there must be at least 2 arguments */
  }
  return r;
}

static int tcl_cmd_subst(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *s = tcl_list_item(args, 1);
  int r = tcl_subst(tcl, tcl_data(s), tcl_length(s));
  tcl_free(s);
  return r;
}

static int tcl_cmd_scan(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *string = tcl_list_item(args, 1);
  struct tcl_value *format = tcl_list_item(args, 2);
  assert(string && format);
  int match = 0;
  const char *sptr = tcl_data(string);
  const char *fptr = tcl_data(format);
  while (*fptr) {
    if (*fptr == '%') {
      fptr++; /* skip '%' */
      char buf[64] = "";
      if (tcl_isdigit(*fptr)) {
        int w = (int)strtol(fptr, (char**)&fptr, 10);
        if (w > 0 && w < sizeof(buf) - 1) {
          strncpy(buf, sptr, w);
          buf[w] = '\0';
          sptr += w;
        }
      }
      int radix = -1;
      int v = 0;
      switch (*fptr++) {
      case 'c':
        if (buf[0]) {
          v = (int)buf[0];
        } else {
          v = (int)*sptr++;
        }
        break;
      case 'd':
        radix = 10;
        break;
      case 'i':
        radix = 0;
        break;
      case 'x':
        radix = 16;
        break;
      }
      if (radix >= 0) {
        if (buf[0]) {
          v = (int)strtol(buf, NULL, radix);
        } else {
          v = (int)strtol(sptr, (char**)&sptr, radix);
        }
      }
      match++;
      struct tcl_value *var = tcl_list_item(args, match + 2);
      if (var) {
        const char *p = tcl_int2string(buf, sizeof buf, 10, v);
        tcl_var(tcl, tcl_data(var), tcl_value(p, strlen(p)));
      }
      tcl_free(var);
    } else if (*fptr == *sptr) {
      fptr++;
      sptr++;
    } else {
      break;
    }
  }
  tcl_free(string);
  tcl_free(format);
  return tcl_numeric_result(tcl, FNORMAL, match);
}

static int tcl_cmd_format(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  size_t bufsize = 256;
  char *buffer = malloc(bufsize);
  if (!buffer) {
    return tcl_error_result(tcl, TCLERR_MEMORY, NULL);
  }
  struct tcl_value *format = tcl_list_item(args, 1);
  assert(format);
  const char *fptr = tcl_data(format);
  size_t buflen = 0;
  int index = 2;
  struct tcl_value *argcopy = NULL;
  while (*fptr) {
    char field[64] = "";
    size_t fieldlen = 0;
    int pad = 0;
    bool left_justify = false;
    if (*fptr == '%' && *(fptr + 1) != '%') {
      fptr++; /* skip '%' */
      if (*fptr == '-') {
        left_justify = true;
        fptr++;
      }
      if (tcl_isdigit(*fptr)) {
        bool zeropad = (*fptr == '0');
        pad = (int)strtol(fptr, (char**)&fptr, 10);
        if (pad <= 0 || pad > sizeof(field) - 1) {
          pad = 0;
        } else {
          memset(field, zeropad ? '0' : ' ', sizeof(field));
        }
      }
      char ival[32];
      const char *pval = NULL;
      int skip = 0;
      argcopy = tcl_list_item(args, index++);
      switch (*fptr) {
      case 'c':
        fieldlen = (pad > 1) ? pad : 1;
        skip = left_justify ? 0 : fieldlen - 1;
        field[skip] = (char)tcl_number(argcopy);
        break;
      case 'd':
      case 'i':
      case 'x':
        pval = tcl_int2string(ival, sizeof(ival), (*fptr == 'x') ? 16 : 10, tcl_number(argcopy));
        fieldlen = strlen(pval);
        if (pad > fieldlen) {
          skip = left_justify ? 0 : pad - fieldlen;
          fieldlen = pad;
        }
        memcpy(field + skip, pval, strlen(pval));
        break;
      case 's':
        fieldlen = tcl_length(argcopy);
        if (pad > fieldlen) {
          fieldlen = pad;
        }
        break;
      }
      if (*fptr != 's' && argcopy) {
        argcopy = tcl_free(argcopy);
      }
    } else {
      fieldlen = 1;
      field[0] = *fptr;
      if (*fptr == '%') {
        assert(*(fptr + 1) == '%'); /* otherwise, should not have dropped in the else clause */
        fptr++;
      }
    }
    if (buflen + fieldlen + 1 >= bufsize) {
      size_t newsize = 2 * bufsize;
      while (buflen + fieldlen + 1 >= newsize) {
        newsize *= 2;
      }
      char *newbuf = malloc(newsize);
      if (newbuf) {
        memcpy(newbuf, buffer, buflen);
        free(buffer);
        buffer = newbuf;
        bufsize = newsize;
      }
    }
    if (buflen + fieldlen + 1 < bufsize) {
      if (argcopy) {
        int slen = tcl_length(argcopy);
        int skip = (pad > slen && !left_justify) ? pad - slen : 0;
        if (pad > slen) {
          memset(buffer + buflen, ' ', pad);
        }
        memcpy(buffer + buflen + skip, tcl_data(argcopy), slen);
      } else {
        memcpy(buffer + buflen, field, fieldlen);
      }
      buflen += fieldlen;
    }
    if (argcopy) {
      argcopy = tcl_free(argcopy);
    }
    fptr++;
  }
  if (buflen + 1 < bufsize) {
    buffer[buflen] = '\0';
  }
  tcl_free(format);
  int r = tcl_result(tcl, FNORMAL, tcl_value(buffer, buflen));
  free(buffer);
  return r;
}

static int tcl_cmd_incr(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int val = 1;
  if (tcl_list_length(args) == 3) {
    struct tcl_value *incr = tcl_list_item(args, 2);
    val = tcl_number(incr);
    tcl_free(incr);
  }
  struct tcl_value *name = tcl_list_item(args, 1);
  assert(name);
  struct tcl_value *v = tcl_var(tcl, tcl_data(name), NULL);
  const char *p = "";
  if (v) {
    char buf[64];
    p = tcl_int2string(buf, sizeof buf, 10, tcl_number(v) + val);
    tcl_var(tcl, tcl_data(name), tcl_value(p, strlen(p)));
  }
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, tcl_value(p, strlen(p)));
}

static int tcl_cmd_append(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  struct tcl_value *name = tcl_list_item(args, 1);
  assert(name);
  struct tcl_value *val = tcl_var(tcl, tcl_data(name), NULL);
  if (val) {
    val = tcl_dup(val); /* make a copy */
    for (int i = 2; i < nargs; i++) {
      struct tcl_value *tail = tcl_list_item(args, i);
      tcl_append(val, tail);
    }
    tcl_var(tcl, tcl_data(name), tcl_dup(val));
  }
  tcl_free(name);
  return val ? tcl_result(tcl, FNORMAL, val) : tcl_error_result(tcl, TCLERR_VARUNKNOWN, NULL);
}

#define SUBCMD(v, s)  (strcmp(tcl_data(v), (s)) == 0)

/* source: https://github.com/cacharle/globule */
static bool tcl_fnmatch(const char *pattern, const char *string) {
  if (*pattern == '\0')
    return (*string == '\0');
  if (*string == '\0')
    return (strcmp(pattern, "*") == 0);
  switch (*pattern) {
  case '*':
    if (tcl_fnmatch(pattern + 1, string))
      return true;
    if (tcl_fnmatch(pattern, string + 1))
      return true;
    return (tcl_fnmatch(pattern + 1, string + 1));
  case '?':
    return (tcl_fnmatch(pattern + 1, string + 1));
  case '[':
    pattern++;
    bool complement = *pattern == '!';
    if (complement)
      pattern++;
    const char *closing = strchr(pattern + 1, ']') + 1;
    if (*pattern == *string)  // has to contain at least one character
      return (!complement ? tcl_fnmatch(closing, string + 1) : false);
    pattern++;
    for (; *pattern != ']'; pattern++) {
      if (pattern[0] == '-' && pattern + 2 != closing) {
        char range_start = pattern[-1];
        char range_end = pattern[1];
        if (*string >= range_start && *string <= range_end)
          return (!complement ? tcl_fnmatch(closing, string + 1) : false);
        pattern++;
      } else if (*pattern == *string)
        return (!complement ? tcl_fnmatch(closing, string + 1) : false);
    }
    return (!complement ? false : tcl_fnmatch(closing, string + 1));
  }
  if (*pattern == *string)
    return (tcl_fnmatch(pattern + 1, string + 1));
  return false;
}

static int tcl_cmd_string(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  int r = FERROR;
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  struct tcl_value *arg1 = tcl_list_item(args, 2);
  if (SUBCMD(subcmd, "length")) {
    r = tcl_numeric_result(tcl, FNORMAL, tcl_length(arg1));
  } else if (SUBCMD(subcmd, "tolower") || SUBCMD(subcmd, "toupper")) {
    bool lcase = SUBCMD(subcmd, "tolower");
    const struct tcl_value *tgt = tcl_dup(arg1);
    size_t sz = tcl_length(tgt);
    char *base = (char*)tcl_data(tgt);
    for (size_t i = 0; i < sz; i++) {
      base[i] = lcase ? tolower(base[i]) : toupper(base[i]);
    }
  } else if (SUBCMD(subcmd, "trim") || SUBCMD(subcmd, "trimleft") || SUBCMD(subcmd, "trimright")) {
    const char *chars = " \t\r\n";
    struct tcl_value *arg2 = NULL;
    if (nargs >= 4) {
      arg2 = tcl_list_item(args, 3);
      chars = tcl_data(arg2);
    }
    const char *first = tcl_data(arg1);
    const char *last = first + tcl_length(arg1);
    if (SUBCMD(subcmd, "trim") || SUBCMD(subcmd, "trimleft")) {
      while (*first && strchr(chars, *first)) {
        first++;
      }
    }
    if (SUBCMD(subcmd, "trim") || SUBCMD(subcmd, "trimright")) {
      while (last>first && strchr(chars, *(last - 1))) {
        last--;
      }
    }
    r = tcl_result(tcl, FNORMAL, tcl_value(first, last - first));
    if (arg2) {
      tcl_free(arg2);
    }
  } else {
    if (nargs < 4) {  /* need at least "string subcommand arg arg" */
      tcl_free(subcmd);
      tcl_free(arg1);
      return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
    }
    struct tcl_value *arg2 = tcl_list_item(args, 3);
    if (SUBCMD(subcmd, "compare")) {
      r = tcl_numeric_result(tcl, FNORMAL, strcmp(tcl_data(arg1), tcl_data(arg2)));
    } else if (SUBCMD(subcmd, "equal")) {
      r = tcl_numeric_result(tcl, FNORMAL, strcmp(tcl_data(arg1), tcl_data(arg2)) == 0);
    } else if (SUBCMD(subcmd, "first") || SUBCMD(subcmd, "last")) {
      int pos = 0;
      if (nargs >= 5) {
        struct tcl_value *arg3 = tcl_list_item(args, 4);
        pos = tcl_number(arg3);
        tcl_free(arg3);
      }
      const char *haystack = tcl_data(arg2);
      const char *needle = tcl_data(arg1);
      const char *p = NULL;
      if (SUBCMD(subcmd, "first")) {
        if (pos < tcl_length(arg2)) {
          p = strstr(haystack + pos, needle);
        }
      } else {
        if (nargs < 5) {
          pos = tcl_length(arg2);
        }
        int len = strlen(needle);
        p = haystack + pos - len;
        while (p >= haystack) {
          if (strncmp(p, needle, len) == 0) {
            break;
          }
          p--;
        }
      }
      r = tcl_numeric_result(tcl, FNORMAL, (p && p >= haystack) ? (p - haystack) : -1);
    } else if (SUBCMD(subcmd, "index")) {
      int pos = tcl_number(arg2);
      if (pos >= tcl_length(arg1)) {
        r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
      } else {
        r = tcl_result(tcl, FNORMAL, tcl_value(tcl_data(arg1) + pos, 1));
      }
    } else if (SUBCMD(subcmd, "match")) {
      r = tcl_numeric_result(tcl, FNORMAL, tcl_fnmatch(tcl_data(arg1), tcl_data(arg2)) == true);
    } else if (SUBCMD(subcmd, "range")) {
      int first = tcl_number(arg2);
      if (first < 0) {
        first = 0;
      }
      int last = INT_MAX;
      if (nargs >= 5) {
        struct tcl_value *arg3 = tcl_list_item(args, 4);
        if (strcmp(tcl_data(arg3), "end") != 0) {
          last = tcl_number(arg3);
        }
        tcl_free(arg3);
      }
      if (last > tcl_length(arg1)) {
        last = tcl_length(arg1);
      }
      r = tcl_result(tcl, FNORMAL, tcl_value(tcl_data(arg1) + first, last - first + 1));
    } else if (SUBCMD(subcmd, "replace")) {
      if (nargs < 6) {  /* need at least "string replace text idx1 idx2 word" */
        tcl_free(subcmd);
        tcl_free(arg1);
        tcl_free(arg2);
        return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
      }
      size_t len = tcl_length(arg1);
      int idx1 = tcl_number(arg2);
      if (idx1 < 0 || idx1 >= len) {
        idx1 = 0;
      }
      struct tcl_value *arg3 = tcl_list_item(args, 4);
      int idx2 = tcl_number(arg3);
      if (idx2 < 0 || idx2 >= len) {
        idx2 = len - 1;
      }
      struct tcl_value *modified = tcl_value(tcl_data(arg1), idx1);
      tcl_append(modified, tcl_dup(tcl_list_item(args, 5)));
      tcl_append(modified, tcl_value(tcl_data(arg1) + idx2 + 1, tcl_length(arg1) - (idx2 + 1)));
      tcl_free(arg3);
      r = tcl_result(tcl, FNORMAL, modified);
    } else {
      r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
    }
    if (arg2) {
      tcl_free(arg2);
    }
  }
  tcl_free(subcmd);
  tcl_free(arg1);
  if (r == FERROR) {
    r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL); /* generic argument error */
  }
  return r;
}

static int tcl_cmd_info(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  int r = FERROR;
  if (SUBCMD(subcmd, "exists")) {
    if (nargs >= 3) {
      struct tcl_value *name = tcl_list_item(args, 2);
      r = tcl_numeric_result(tcl, FNORMAL, (tcl_findvar(tcl->env, tcl_data(name)) != NULL));
      tcl_free(name);
    }
  } else if (SUBCMD(subcmd, "tclversion")) {
    r = tcl_result(tcl, FNORMAL, tcl_value("1.0", 3));
  } else {
    r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
  }
  tcl_free(subcmd);
  if (r == FERROR) {
    r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL); /* generic argument error */
  }
  return r;
}

static int tcl_cmd_array(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  struct tcl_value *name = tcl_list_item(args, 2);
  int r = FERROR;
  if (SUBCMD(subcmd, "length") || SUBCMD(subcmd, "size")) {
    struct tcl_var *var = tcl_findvar(tcl->env, tcl_data(name));
    if (var && var->env) { /* found local alias of a global/upvar; find the global/upvar */
      var = tcl_findvar(var->env, tcl_alias_name(var));
    }
    int count = 0;
    if (var) {
      for (int i = 0; i < var->elements; i++) {
        if (var->value[i]) {
          count++;
        }
      }
    }
    r = tcl_numeric_result(tcl, FNORMAL, count);
  } else if (SUBCMD(subcmd, "slice")) {
    if (nargs < 4) {  /* need at least "array slice var blob" */
      tcl_free(subcmd);
      tcl_free(name);
      return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
    }
    struct tcl_value *blob = tcl_list_item(args, 3);
    const unsigned char *bptr = (const unsigned char*)tcl_data(blob);
    size_t blen = tcl_length(blob);
    struct tcl_value *wsize = (nargs > 4) ? tcl_list_item(args, 4) : NULL;
    int step = wsize ? tcl_number(wsize) : 1;
    if (step < 1) {
      step = 1;
    }
    if (wsize) {
      tcl_free(wsize);
    }
    struct tcl_value *wendian = (nargs > 5) ? tcl_list_item(args, 5) : NULL;
    bool bigendian = wendian ? strcmp(tcl_data(wendian), "be") == 0 : false;
    if (wendian) {
      tcl_free(wendian);
    }
    int count = 0;
    struct tcl_var *var = NULL;
    while (blen > 0) {
      /* make value (depending on step size) and convert to string */
      tcl_int value = 0;
      for (int i = 0; i < step && i < blen; i++) {
        if (bigendian) {
          value |= (tcl_int)*(bptr + i) << 8 * (step - 1 - i);
        } else {
          value |= (tcl_int)*(bptr + i) << 8 * i;
        }
      }
      char buf[64];
      const char *p = tcl_int2string(buf, sizeof buf, 10, value);
      if (!var) {
        /* make the variable (implicitly sets index 0), find it back */
        tcl_var(tcl, tcl_data(name), tcl_value(p, strlen(p)));
        var = tcl_findvar(tcl->env, tcl_data(name));
        assert(var);            /* if it didn't yet exist, it was just created */
        if (var->env) {         /* found local alias of a global/upvar; find the global/upvar */
          var = tcl_findvar(var->env, tcl_alias_name(var));
        }
        /* can immediately allocate the properly sized value list */
        int numelements = blen / step + 1;
        struct tcl_value **newlist = malloc(numelements * sizeof(struct tcl_value*));
        if (newlist) {
          memset(newlist, 0, numelements * sizeof(struct tcl_value*));
          assert(var->elements == 1);
          newlist[0] = var->value[0];
          free(var->value);
          var->value = newlist;
          var->elements = numelements;
        } else {
          tcl_error_result(tcl, TCLERR_MEMORY, NULL);
          count = 0;
          break;
        }
      } else {
        assert(count < var->elements);
        var->value[count] = tcl_value(p, strlen(p));
      }
      count++;
      bptr += step;
      blen = (blen > step) ? blen - step : 0;
    }
    tcl_free(blob);
    r = tcl_numeric_result(tcl, (count > 0) ? FNORMAL : FERROR, count);
  } else if (SUBCMD(subcmd, "split")) {
    if (nargs < 4) {  /* need at least "array slice var string" */
      tcl_free(subcmd);
      tcl_free(name);
      return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
    }
    char varname[MAX_VAR_LENGTH];
    struct tcl_value *v_string = tcl_list_item(args, 3);
    const char *string = tcl_data(v_string);
    size_t string_len = tcl_length(v_string);
    struct tcl_value *v_sep = (tcl_list_length(args) > 4) ? tcl_list_item(args, 4) : NULL;
    const char *chars = v_sep ? tcl_data(v_sep) : " \t\r\n";
    const char *start = string;
    const char *end = start;
    int index = 0;
    while (end - string < string_len) {
      assert(*end);
      if (strchr(chars, *end)) {
        sprintf(varname, "%s(%d)", tcl_data(name), index);
        tcl_var(tcl, varname, tcl_value(start, end - start));
        start = end + 1;
        index += 1;
      }
      end++;
    }
    /* append last item */
    sprintf(varname, "%s(%d)", tcl_data(name), index++);
    tcl_var(tcl, varname, tcl_value(start, end - start));
    tcl_free(v_string);
    if (v_sep) {
      tcl_free(v_sep);
    }
    r = tcl_numeric_result(tcl, (index > 0) ? FNORMAL : FERROR, index);
  } else {
    r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
  }
  tcl_free(subcmd);
  tcl_free(name);
  if (r == FERROR) {
    r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL); /* generic argument error */
  }
  return r;
}

static int tcl_cmd_list(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_new();
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    tcl_list_append(list, tcl_list_item(args, i));
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_concat(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_new();
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    struct tcl_value *sublst = tcl_list_item(args, i);
    int sublst_len = tcl_list_length(sublst);
    for (int j = 0; j < sublst_len; j++) {
      tcl_list_append(list, tcl_list_item(sublst, j));
    }
    tcl_free(sublst);
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_lappend(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int n = tcl_list_length(args);
  /* check whether the value exists */
  struct tcl_value *name = tcl_list_item(args, 1);
  struct tcl_var *var = tcl_findvar(tcl->env, tcl_data(name));
  if (var && var->env) {    /* found local alias of a global/upvar; find the global/upvar */
    var = tcl_findvar(var->env, tcl_alias_name(var));
  }
  struct tcl_value *list;
  if (var) {
    list = tcl_var(tcl, tcl_data(name), NULL);
    assert(list); /* it was already checked that the variable exists */
  } else {
    /* variable does not exist, create empty list and create variable */
    list = tcl_list_new();
    tcl_var(tcl, tcl_data(name), list);
  }
  /* append other arguments, update the variable */
  for (int i = 2; i < n; i++) {
    tcl_list_append(list, tcl_list_item(args, i));
  }
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, tcl_dup(list));
}

static int tcl_cmd_lreplace(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  struct tcl_value *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  struct tcl_value *v_first = tcl_list_item(args, 2);
  int first = tcl_number(v_first);
  tcl_free(v_first);
  struct tcl_value *v_last = tcl_list_item(args, 3);
  int last = (strcmp(tcl_data(v_last), "end") == 0) ? list_len - 1 : tcl_number(v_last);
  tcl_free(v_last);
  struct tcl_value *rangelist = tcl_list_new();
  /* copy up to "first" elements from the original list */
  for (int i = 0; i < first; i++) {
    tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  /* append arguments after the lreplace command */
  for (int i = 4; i < nargs; i++) {
    tcl_list_append(rangelist, tcl_list_item(args, i));
  }
  /* copy the items behind "last" from the original list */
  for (int i = last + 1; i < list_len; i++) {
    tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  tcl_free(list);
  return tcl_result(tcl, FNORMAL, rangelist);
}

static int tcl_cmd_llength(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_item(args, 1);
  int n = tcl_list_length(list);
  tcl_free(list);
  return tcl_numeric_result(tcl, FNORMAL, n);
}

static int tcl_cmd_lindex(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_item(args, 1);
  struct tcl_value *v_index = tcl_list_item(args, 2);
  int index = tcl_number(v_index);
  tcl_free(v_index);
  int n = tcl_list_length(list);
  int r = FNORMAL;
  if (index < n) {
    r = tcl_result(tcl, FNORMAL, tcl_list_item(list, index));
  } else {
    r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
  }
  tcl_free(list);
  return r;
}

static int tcl_cmd_lrange(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  struct tcl_value *v_first = tcl_list_item(args, 2);
  int first = tcl_number(v_first);
  tcl_free(v_first);
  struct tcl_value *v_last = tcl_list_item(args, 3);
  int last = (strcmp(tcl_data(v_last), "end") == 0) ? list_len - 1 : tcl_number(v_last);
  tcl_free(v_last);
  struct tcl_value *rangelist = tcl_list_new();
  for (int i = first; i <= last; i++) {
    tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  tcl_free(list);
  return tcl_result(tcl, FNORMAL, rangelist);
}

static int tcl_cmd_split(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *v_string = tcl_list_item(args, 1);
  const char *string = tcl_data(v_string);
  size_t string_len = tcl_length(v_string);
  struct tcl_value *v_sep = (tcl_list_length(args) > 2) ? tcl_list_item(args, 2) : NULL;
  const char *chars = v_sep ? tcl_data(v_sep) : " \t\r\n";
  struct tcl_value *list = tcl_list_new();
  const char *start = string;
  const char *end = start;
  while (end - string < string_len) {
    assert(*end);
    if (strchr(chars, *end)) {
      tcl_list_append(list, tcl_value(start, end - start));
      start = end + 1;
    }
    end++;
  }
  /* append last item */
  tcl_list_append(list, tcl_value(start, end - start));
  tcl_free(v_string);
  if (v_sep) {
    tcl_free(v_sep);
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_join(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  struct tcl_value *sep = (tcl_list_length(args) >= 3) ? tcl_list_item(args, 2) : tcl_value(" ", 1);
  struct tcl_value *string = tcl_value("", 0);
  for (int i = 0; i < list_len; i++) {
    tcl_append(string, tcl_list_item(list, i));
    if (i + 1 < list_len && tcl_length(sep) > 0) {
      tcl_append(string, tcl_dup(sep));
    }
  }
  tcl_free(list);
  tcl_free(sep);
  return tcl_result(tcl, FNORMAL, string);
}

#if !defined TCL_DISABLE_BINARY
static bool binary_fmt(const char **source, unsigned *width, unsigned *count, bool *is_signed, bool *is_bigendian) {
  assert(source != NULL);
  const char *src = *source;
  assert(src != NULL);
  assert(width != NULL);
  switch (*src) {
  case 'c':   /* 8-bit integer */
    *width = 1;
    break;
  case 's':   /* 16-bit integer */
  case 'S':
    *width = 2;
    break;
  case 'i':   /* 32-bit integer */
  case 'I':
    *width = 4;
    break;
  case 'w':   /* 64-bit integer */
  case 'W':
    *width = 8;
    break;
  default:
    return false;
  }
  assert(is_bigendian != NULL);
  *is_bigendian = isupper(*src);
  src++; /* skip type letter */
  assert(is_signed != NULL);
  *is_signed = true;
  if (*src == 'u') {
    *is_signed = false;
    src++;
  }
  assert(count != NULL);
  *count = 1;
  if (isdigit(*src)) {
    *count = (unsigned)strtol(src, (char**)&src, 10);
  } else if (*src == '*') {
    *count = UINT_MAX;
    src++;
  }
  if (count == 0) {
    return false;
  }
  *source = src;
  return true;
}

static int tcl_cmd_binary(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FERROR;
  int nargs = tcl_list_length(args);
  int reqargs = 4, fmtidx = 2;
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  if (SUBCMD(subcmd, "scan")) {
    reqargs = 5;
    fmtidx = 3;
  }
  if (nargs < reqargs) {
    tcl_free(subcmd);
    return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
  }

  struct tcl_value *fmt = tcl_list_item(args, fmtidx);
  const char *fmtraw = tcl_data(fmt);
  int numvars = nargs - (fmtidx + 1); /* first argument is behind the format string */
  if (SUBCMD(subcmd, "format")) {
    /* syntax "binary format fmt arg ..." */
    /* get data size */
    size_t datalen = 0;
    const char *ftmp = fmtraw;
    for (int i = 0; i < numvars; i++) {
      unsigned width, count;
      bool sign_extend, is_bigendian;
      if (!binary_fmt(&ftmp, &width, &count, &sign_extend, &is_bigendian)) {
        tcl_free(subcmd);
        tcl_free(fmt);
        return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
      }
      if (count > numvars) {
        count = numvars;
      }
      datalen+=width*count;
    }
    char *rawdata = malloc(datalen);
    if (rawdata != NULL) {
      int dataidx = 0;
      unsigned width, count = 0;
      bool sign_extend, is_bigendian;
      for (int varidx = 0; varidx < numvars; varidx++) {
        if (count == 0) {
          binary_fmt(&fmtraw, &width, &count, &sign_extend, &is_bigendian);
        }
        struct tcl_value *argvalue = tcl_list_item(args, varidx + fmtidx + 1);
        tcl_int val = tcl_number(argvalue);
        tcl_free(argvalue);
        memcpy(rawdata + dataidx, &val, width);
        if (is_bigendian) {
          unsigned low = 0;
          unsigned high = width - 1;
          while (low < high) {
            unsigned char t = rawdata[dataidx + low];
            rawdata[dataidx + low] = rawdata[dataidx + high];
            rawdata[dataidx + high] = t;
            low++;
            high--;
          }
        }
        dataidx += width;
        count--;
      }
      r = tcl_result(tcl, FNORMAL, tcl_value(rawdata, datalen));
      free(rawdata);
    } else {
      r = tcl_error_result(tcl, TCLERR_MEMORY, NULL);
    }
  } else if (SUBCMD(subcmd, "scan")) {
    /* syntax "binary scan data fmt var ..." */
    struct tcl_value *data = tcl_list_item(args, 2);
    size_t datalen = tcl_length(data);
    char *rawdata = malloc(datalen);  /* make a copy of the data */
    if (rawdata == NULL) {
      tcl_free(subcmd);
      tcl_free(fmt);
      tcl_free(data);
      return tcl_error_result(tcl, TCLERR_MEMORY, NULL);
    }
    memcpy(rawdata, tcl_data(data), datalen);
    tcl_free(data);
    int dataidx = 0;
    int cvtcount = 0;
    for (int varidx = 0; varidx < numvars; varidx++) {
      /* get variable name */
      char varname[128];
      struct tcl_value *var = tcl_list_item(args, varidx + fmtidx + 1);
      strlcpy(varname, tcl_data(var), sizeof varname);
      tcl_free(var);
      /* get field format */
      unsigned width, count;
      bool sign_extend, is_bigendian;
      if (!binary_fmt(&fmtraw, &width, &count, &sign_extend, &is_bigendian)) {
        tcl_free(subcmd);
        tcl_free(fmt);
        free(rawdata);
        return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
      }
      /* get & format the data */
      struct tcl_value *value = NULL;
      assert(count > 0);
      assert(width > 0);
      for (unsigned c = 0; c < count && dataidx + width <= datalen; c++) {
        if (is_bigendian) {
          /* convert Big Endian to Little Endian before moving to numeric value */
          unsigned low = 0;
          unsigned high = width - 1;
          while (low < high) {
            unsigned char t = rawdata[dataidx + low];
            rawdata[dataidx + low] = rawdata[dataidx + high];
            rawdata[dataidx + high] = t;
            low++;
            high--;
          }
        }
        tcl_int val = 0;
        /* for sign extension, look at the sign bit of the last byte (now that the
           bytes are stored in Little Endian) */
        if (sign_extend) {
          unsigned high = width - 1;
          if (rawdata[dataidx + high] & 0x80) {
            val = -1;
          }
        }
        memcpy(&val, rawdata + dataidx, width);
        dataidx += width;
        /* store data */
        char field[30];
        const char *fptr = tcl_int2string(field, sizeof field, 10, val);
        if (count == 1) {
          value = tcl_value(fptr, strlen(fptr));
        } else {
          if (c == 0) {
            value = tcl_list_new();
          }
          tcl_list_append(value, tcl_value(fptr, strlen(fptr)));
        }
      }
      if (value) {
        tcl_var(tcl, varname, value);
        cvtcount++;
      }
    }
    free(rawdata);
    r = tcl_numeric_result(tcl, FNORMAL, cvtcount);
  } else {
    r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
  }
  tcl_free(subcmd);
  tcl_free(fmt);
  return r;
}
#endif

#if !defined TCL_DISABLE_CLOCK
#include <time.h>

static int tcl_cmd_clock(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FERROR;
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  if (SUBCMD(subcmd, "seconds")) {
    char buffer[20];
    sprintf(buffer, "%ld", (long)time(NULL));
    r = tcl_result(tcl, FNORMAL, tcl_value(buffer, strlen(buffer)));
  } else if (SUBCMD(subcmd, "format")) {
    int argcount = tcl_list_length(args);
    if (argcount < 3) {
      r = tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
    } else {
      struct tcl_value *v_tstamp = tcl_list_item(args, 2);
      time_t tstamp = (time_t)tcl_number(v_tstamp);
      tcl_free(v_tstamp);
      const struct tm *timeinfo = localtime(&tstamp);
      struct tcl_value *v_format = (tcl_list_length(args) > 3) ? tcl_list_item(args, 3) : NULL;
      const char *format = v_format ? tcl_data(v_format) : "%Y-%m-%d %H:%M:%S";
      char buffer[50];
      strftime(buffer, sizeof buffer, format, timeinfo);
      r = tcl_result(tcl, FNORMAL, tcl_value(buffer, strlen(buffer)));
      if (v_format) {
        tcl_free(v_format);
      }
    }
  } else {
    r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
  }
  tcl_free(subcmd);
  return r;
}
#endif

#if !defined TCL_DISABLE_PUTS && !defined TCL_DISABLE_FILEIO
static int tcl_cmd_puts(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fd = NULL;
  struct tcl_value *text = NULL;
  int r = FNORMAL;
  if (tcl_list_length(args) == 3) {
    fd = tcl_list_item(args, 1);
    text = tcl_list_item(args, 2);
    if (fileno((FILE*)tcl_number(fd)) < 0) {
      r = tcl_error_result(tcl, TCLERR_FILEIO, NULL);
    } else {
      fputs(tcl_data(text), (FILE*)tcl_number(fd));
    }
  } else {
    text = tcl_list_item(args, 1);
    puts(tcl_data(text));
  }
  tcl_free(text);
  if (fd) {
    tcl_free(fd);
  }
  return (r == FNORMAL) ? tcl_empty_result(tcl) : r;
}
#endif

#if !defined TCL_DISABLE_FILEIO
#include <io.h>
#include <sys/stat.h>

static int tcl_cmd_open(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *path = tcl_list_item(args, 1);
  struct tcl_value *mode = (tcl_list_length(args) == 3) ? tcl_list_item(args, 2) : NULL;
# if defined _WIN32 || defined _WIN64
    char buffer[_MAX_PATH];
    strlcpy(buffer, tcl_data(path), sizeof buffer);
    char *p;
    while ((p = strchr(buffer, '/')) != NULL) {
      *p = '\\';
    }
    p = buffer;
#else
    const char *p = tcl_data(path);
# endif
  FILE *fp = fopen(p, mode ? tcl_data(mode) : "r");
  int r = FNORMAL;
  if (fp) {
    r = tcl_numeric_result(tcl, FNORMAL, (tcl_int)fp);
  } else {
    r = tcl_error_result(tcl, TCLERR_FILEIO, tcl_data(path));
  }
  tcl_free(path);
  if (mode) {
    tcl_free(mode);
  }
  return r;
}

static int tcl_cmd_close(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fh = tcl_list_item(args, 1);
  int r = fclose((FILE*)tcl_number(fh));
  tcl_free(fh);
  return (r == 0) ? tcl_empty_result(tcl) : tcl_error_result(tcl, TCLERR_FILEIO, NULL);
}

static int tcl_cmd_seek(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fh = tcl_list_item(args, 1);
  struct tcl_value *offset = tcl_list_item(args, 2);
  int org = SEEK_SET;
  if (tcl_list_length(args) == 4) {
    struct tcl_value *origin = tcl_list_item(args, 3);
    if (strcmp(tcl_data(origin), "current")) {
      org = SEEK_CUR;
    } else if (strcmp(tcl_data(origin), "end")) {
      org = SEEK_END;
    }
    tcl_free(origin);
  }
  fseek((FILE *)tcl_number(fh), (long)tcl_number(offset), org);
  tcl_free(fh);
  tcl_free(offset);
  return tcl_empty_result(tcl);
}

static int tcl_cmd_tell(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fh = tcl_list_item(args, 1);
  long r = ftell((FILE*)tcl_number(fh));
  tcl_free(fh);
  return tcl_numeric_result(tcl, FNORMAL, r);
}

static int tcl_cmd_eof(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fh = tcl_list_item(args, 1);
  int r = feof((FILE*)tcl_number(fh));
  tcl_free(fh);
  return tcl_numeric_result(tcl, FNORMAL, r);
}

static int tcl_cmd_read(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fh = tcl_list_item(args, 1);
  long bytecount = LONG_MAX;
  if (tcl_list_length(args) == 3) {
    struct tcl_value *bytes = tcl_list_item(args, 2);
    bytecount = tcl_number(bytes);
    tcl_free(bytes);
  }
  FILE *fp = ((FILE*)tcl_number(fh));
  tcl_free(fh);
  /* check how many bytes to read (especially if no "bytecount" argument was given) */
  long pos = ftell(fp);
  fseek(fp, 0, SEEK_END);
  long remaining = ftell(fp) - pos;
  fseek(fp, pos, SEEK_SET);
  if (bytecount > remaining) {
    bytecount = remaining;
  }
  char *buffer = malloc(bytecount);
  if (buffer == NULL) {
    return tcl_error_result(tcl, TCLERR_MEMORY, NULL);
  }
  size_t count = fread(buffer, 1, bytecount, fp);
  assert(count <= bytecount); /* can be smaller when \r\n is translated to \n */
  struct tcl_value *result = tcl_value(buffer, count);
  free(buffer);
  return tcl_result(tcl, FNORMAL, result);
}

static int tcl_cmd_gets(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  struct tcl_value *fd = tcl_list_item(args, 1);
  if (fileno((FILE*)tcl_number(fd)) < 0) {
    tcl_free(fd);
    return tcl_error_result(tcl, TCLERR_FILEIO, NULL);
  }
  char buffer[1024];
  const char *p = fgets(buffer, sizeof(buffer), (FILE*)tcl_number(fd));
  tcl_free(fd);
  if (p == NULL) {
    return tcl_empty_result(tcl);
  }
  char *newline = strchr(buffer, '\n');
  if (newline) {
    *newline = '\0';  /* remove trailing newline (because puts adds it) */
  }
  struct tcl_value *result = tcl_value(buffer, strlen(buffer));
  if (tcl_list_length(args) == 3) {
    struct tcl_value *varname = tcl_list_item(args, 2);
    tcl_var(tcl, tcl_data(varname), tcl_dup(result));
    tcl_free(varname);
  }
  return tcl_result(tcl, FNORMAL, result);
}

static int tcl_cmd_file(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FERROR;
  struct tcl_value *subcmd = tcl_list_item(args, 1);
  struct tcl_value *path = tcl_list_item(args, 2);
# if defined _WIN32 || defined _WIN64
    char buffer[_MAX_PATH];
    strlcpy(buffer, tcl_data(path), sizeof buffer);
    char *pname;
    while ((pname = strchr(buffer, '/')) != NULL) {
      *pname = '\\';
    }
    pname = buffer;
#else
    const char *pname = tcl_data(path);
# endif
  if (SUBCMD(subcmd, "dirname")) {
    const char *p = strrchr(pname, '/');
    size_t len = 1;
    if (p) {
      if (p != pname) {
        len = p - pname;  /* there is a directory in the path, strip off the last '/' */
      }
    } else {
      p = ".";            /* there is no directory in the path, set a '.' */
    }
    r = tcl_result(tcl, FNORMAL, tcl_value(p, len));
  } else if (SUBCMD(subcmd, "exists")) {
    r = tcl_numeric_result(tcl, FNORMAL, (access(pname, 0) == 0));
  } else if (SUBCMD(subcmd, "extension")) {
    const char *p = strrchr(pname, '.');
    if (p && strchr(p, '/') == NULL) {
      r = tcl_result(tcl, FNORMAL, tcl_value(p, strlen(p)));
    } else {
      r = tcl_empty_result(tcl);
    }
  } else if (SUBCMD(subcmd, "isdirectory")) {
    struct stat st;
    int i = stat(pname, &st);
    r = tcl_numeric_result(tcl, FNORMAL, (i == 0) ? (st.st_mode & _S_IFDIR) != 0 : 0);
  } else if (SUBCMD(subcmd, "isfile")) {
    struct stat st;
    int i = stat(pname, &st);
    r = tcl_numeric_result(tcl, FNORMAL, (i == 0) ? (st.st_mode & _S_IFREG) != 0 : 0);
  } else if (SUBCMD(subcmd, "rootname")) {
    const char *p = strrchr(pname, '.');
    if (p && strchr(p, '/') == NULL) {
      r = tcl_result(tcl, FNORMAL, tcl_value(pname, p - pname));
    } else {
      r = tcl_result(tcl, FNORMAL, tcl_value(pname, strlen(pname)));
    }
  } else if (SUBCMD(subcmd, "size")) {
    struct stat st;
    int i = stat(pname, &st);
    r = tcl_numeric_result(tcl, FNORMAL, (i == 0) ? st.st_size : 0);
  } else if (SUBCMD(subcmd, "tail")) {
    const char *p = strrchr(pname, '/');
    p = p ? p + 1 : pname;
    r = tcl_result(tcl, FNORMAL, tcl_value(p, strlen(p)));
  } else {
    r = tcl_error_result(tcl, TCLERR_SUBCMD, tcl_data(subcmd));
  }
  tcl_free(subcmd);
  tcl_free(path);
  return r;
}
#endif

static int tcl_user_proc(struct tcl *tcl, struct tcl_value *args, void *arg) {
  struct tcl_value *code = (struct tcl_value *)arg;
  struct tcl_value *paramlist = tcl_list_item(code, 2);
  struct tcl_value *body = tcl_list_item(code, 3);
  tcl->env = tcl_env_alloc(tcl->env);
  /* copy arguments to parameters (local variables) */
  unsigned paramlist_len = tcl_list_length(paramlist);
  unsigned arglist_len = tcl_list_length(args) - 1; /* first "argument" is the command name, ignore it */
  if (arglist_len > paramlist_len) {
    /* this happens for a user procedure with variable arguments, ignore the
       last argument for now, but handle it separately after the fixed arguments */
    paramlist_len--;  /* this is the number of fixed arguments (which may be zero) */
  }
  for (unsigned i = 0; i < paramlist_len; i++) {
    struct tcl_value *param = tcl_list_item(paramlist, i);
    struct tcl_value *v;
    if (i < arglist_len) {
      /* argument is passed */
      v = tcl_list_item(args, i + 1);
    } else {
      /* argument is *not* passed, use default value */
      assert(tcl_list_length(param) == 2);  /* this should have been checked when registering the user procedure */
      v = tcl_list_item(param, 1);
    }
    if (tcl_list_length(param) > 1) {
      struct tcl_value *p = tcl_list_item(param, 0);
      tcl_free(param);
      param = p;
    }
    tcl_var(tcl, tcl_data(param), v);
    tcl_free(param);
  }
  if (arglist_len > paramlist_len + 1) {
#   if !defined NDEBUG
      struct tcl_value *param = tcl_list_item(paramlist, paramlist_len);
      assert(strcmp(tcl_data(param), "args") == 0);
      tcl_free(param);
#   endif
    struct tcl_value *lst = tcl_list_new();
    for (unsigned i = paramlist_len; i < arglist_len; i++) {
      struct tcl_value *v = tcl_list_item(args, i + 1);
      tcl_list_append(lst, v);
    }
    tcl_var(tcl, "args", lst);
  }
  int r = tcl_eval(tcl, tcl_data(body), tcl_length(body) + 1);
  if (r == FERROR) {
    size_t error_offs = tcl->env->errinfo.currentpos - tcl->env->errinfo.codebase;
    /* need to calculate the offset of the body relative to the start of the
       proc declaration */
    const char *body_ptr;
    size_t body_sz;
    tcl_list_item_ptr(code, 3, &body_ptr, &body_sz);
    error_offs += body_ptr - tcl_data(code);
    /* need to find the proc again */
    struct tcl_value *cmdname = tcl_list_item(code, 1);
    struct tcl_cmd *cmd = tcl_lookup_cmd(tcl, cmdname);
    tcl_free(cmdname);
    assert(cmd);  /* it just ran, so it must be found */
    struct tcl_env *global_env = tcl_env_scope(tcl, 0);
    global_env->errinfo.currentpos = cmd->declpos + error_offs;
  }
  tcl->env = tcl_env_free(tcl->env);
  tcl_free(paramlist);
  tcl_free(body);
  assert(r != FBREAK && r != FCONT);
  return (r == FRETURN) ? FNORMAL : r;
}

static int tcl_cmd_proc(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FNORMAL;
  struct tcl_value *name = tcl_list_item(args, 1);
  struct tcl_value *paramlist = tcl_list_item(args, 2);
  unsigned paramcount = 1;    /* include proc name in parameter count */
  unsigned defaultcount = 0;  /* check whether parameters have default values */
  bool is_varargs = false;    /* check for variable number of arguments */
  unsigned paramlist_len = tcl_list_length(paramlist);
  for (unsigned i = 0; i < paramlist_len; i++) {
    struct tcl_value *param = tcl_list_item(paramlist, i);
    int len = tcl_list_length(param);
    assert(len >= 0);
    if (len == 0 || is_varargs) {
      r = tcl_error_result(tcl, TCLERR_NAMEINVALID, tcl_data(param)); /* invalid name */
    } else if ((len == 1 && defaultcount > 0) || len > 2) {
      r = tcl_error_result(tcl, TCLERR_DEFAULTVAL, tcl_data(param));  /* parameters with default values must come behind parameters without defaults */
    } else if (len == 2) {
      defaultcount++;
    } else {
      paramcount++;
    }
    if (strcmp(tcl_data(param), "args") == 0) {
      is_varargs = true;
      if (len != 1) {
        r = tcl_error_result(tcl, TCLERR_DEFAULTVAL, tcl_data(param));/* special parameter "args" may not have a default value */
      }
    }
    tcl_free(param);
  }
  unsigned max_params = is_varargs ? 0 : paramcount + defaultcount;
  struct tcl_cmd *cmd = tcl_register(tcl, tcl_data(name), tcl_user_proc, paramcount, max_params, tcl_dup(args));
  tcl_free(name);
  tcl_free(paramlist);
  struct tcl_env *global_env = tcl_env_scope(tcl, 0);
  cmd->declpos = global_env->errinfo.currentpos;
  return r == FERROR ? r : tcl_empty_result(tcl);
}

static struct tcl_value *tcl_make_condition_list(struct tcl_value *cond) {
  assert(cond);
  /* add the implied "expr" in front of the condition, except if either:
     - the condition is enveloped between [...] (so it is already evaluated)
     - the condition is a number (so there is nothing to evaluate) */
  if (tcl_isnumber(cond)) {
    return cond;
  } else {
    const char *data = tcl_data(cond);
    size_t len = tcl_length(cond);
    if (len >= 2 && *data == '[' && *(data + len - 1) == ']') {
      size_t i;
      for (i = 1; i < len - 1 && data[i] != '[' && data[i] != ']' && data[i] != '\\'; i++)
        {}
      if (i == len - 1) {
        return cond;  /* expression between [...] and no nested [...] or escapes */
      }
    }
  }
  struct tcl_value *list = tcl_list_new();
  tcl_list_append(list, tcl_value("expr", 4));
  tcl_list_append(list, cond);
  return list;
}

int tcl_eval_condition(struct tcl *tcl, struct tcl_value *cond) {
  assert(cond);
  const char *data = tcl_data(cond);
  size_t len = tcl_length(cond);
  int r = FNORMAL;
  if ((len >= 2 && *data == '[' && *(data + len - 1) == ']')) {
    r = tcl_subst(tcl, data, len);
  } else if (tcl_isnumber(cond)) {
    r = tcl_numeric_result(tcl, FNORMAL, tcl_number(cond));
  } else {
    r = tcl_eval(tcl, tcl_data(cond), tcl_length(cond) + 1);
  }
  return r;
}

static int tcl_cmd_if(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int i = 1;
  int n = tcl_list_length(args);
  int r = tcl_empty_result(tcl);
  while (i < n) {
    struct tcl_value *cond = tcl_make_condition_list(tcl_list_item(args, i++));
    struct tcl_value *branch = (i < n) ? tcl_list_item(args, i++) : NULL;
    if (strcmp(tcl_data(branch), "then") == 0) {
      tcl_free(branch); /* ignore optional keyword "then", get next branch */
      branch = (i < n) ? tcl_list_item(args, i++) : NULL;
    }
    r = tcl_eval_condition(tcl, cond);
    tcl_free(cond);
    if (r != FNORMAL) {
      tcl_free(branch);   /* error in condition expression, abort */
      break;
    } else if (!branch) {
      return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
    }
    if (tcl_number(tcl->result)) {
      r = tcl_eval(tcl, tcl_data(branch), tcl_length(branch) + 1);
      tcl_free(branch);
      break;              /* branch taken, do not take any other branch */
    }
    branch = tcl_free(branch);
    /* "then" branch not taken, check how to continue, first check for keyword */
    if (i < n) {
      branch = tcl_list_item(args, i);
      if (strcmp(tcl_data(branch), "elseif") == 0) {
        branch = tcl_free(branch);
        i++;              /* skip the keyword (then drop back into the loop,
                             parsing the next condition) */
      } else if (strcmp(tcl_data(branch), "else") == 0) {
        branch = tcl_free(branch);
        i++;              /* skip the keyword */
        if (i < n) {
          branch = tcl_list_item(args, i++);
          r = tcl_eval(tcl, tcl_data(branch), tcl_length(branch) + 1);
          tcl_free(branch);
          break;          /* "else" branch taken, do not take any other branch */
        } else {
          return tcl_error_result(tcl, TCLERR_ARGUMENT, NULL);
        }
      } else if (i + 1 < n) {
        /* no explicit keyword, but at least two blocks in the list:
           assume it is {cond} {branch} (implied elseif) */
        branch = tcl_free(branch);
      } else {
        /* last block: must be (implied) else */
        i++;
        r = tcl_eval(tcl, tcl_data(branch), tcl_length(branch) + 1);
        branch = tcl_free(branch);
      }
    }

  }
  return r;
}

static int tcl_cmd_switch(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  int r = tcl_empty_result(tcl);
  struct tcl_value *crit = tcl_list_item(args, 1);
  /* there are two forms of switch: all pairs in a list, or all pairs simply
     appended onto the tail of the command */
  struct tcl_value *list;
  int list_idx, list_len;
  if (nargs == 3) {
    list = tcl_list_item(args, 2);
    list_idx = 0;
    list_len = tcl_list_length(list);
  } else {
    list = args;
    list_idx = 2;
    list_len = nargs;
  }
  /* find a match */
  while (list_idx < list_len) {
    struct tcl_value *pattern = tcl_list_item(list, list_idx);
    bool match = (strcmp(tcl_data(pattern), "default") == 0 ||
                  tcl_fnmatch(tcl_data(pattern), tcl_data(crit)));
    tcl_free(pattern);
    if (match) {
      break;
    }
    list_idx += 2;  /* skip pattern & body pair */
  }
  /* find body */
  struct tcl_value *body = NULL;
  list_idx += 1;
  while (list_idx < list_len) {
    body = tcl_list_item(list, list_idx);
    if (strcmp(tcl_data(body), "-") != 0)
      break;
    body = tcl_free(body);
    list_idx += 2;  /* body, plus pattern of the next case */
  }
  /* clean up values that are no longer needed */
  tcl_free(crit);
  if (nargs == 3) {
    tcl_free(list);
  }
  /* execute the body */
  if (body) {
    r = tcl_eval(tcl, tcl_data(body), tcl_length(body) + 1);
    tcl_free(body);
  }
  return r;
}

static int tcl_cmd_while(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 3);
  struct tcl_value *cond = tcl_make_condition_list(tcl_list_item(args, 1));
  struct tcl_value *body = tcl_list_item(args, 2);
  int r = FNORMAL;
  for (;;) {
    r = tcl_eval_condition(tcl, cond);
    if (r != FNORMAL) {
      break;
    }
    if (!tcl_number(tcl->result)) {
      r = FNORMAL;
      break;
    }
    r = tcl_eval(tcl, tcl_data(body), tcl_length(body) + 1);
    if (r != FCONT && r != FNORMAL) {
      assert(r == FBREAK || r == FRETURN || r == FEXIT || r == FERROR);
      if (r == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
  }
  tcl_free(cond);
  tcl_free(body);
  return r;
}

static int tcl_cmd_for(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 5);
  struct tcl_value *setup = tcl_list_item(args, 1);
  int r = tcl_eval(tcl, tcl_data(setup), tcl_length(setup) + 1);
  tcl_free(setup);
  if (r != FNORMAL) {
    return r;
  }
  struct tcl_value *cond = tcl_make_condition_list(tcl_list_item(args, 2));
  struct tcl_value *post = tcl_list_item(args, 3);
  struct tcl_value *body = tcl_list_item(args, 4);
  for (;;) {
    r = tcl_eval_condition(tcl, cond);
    if (r != FNORMAL) {
      break;
    }
    if (!tcl_number(tcl->result)) {
      r = FNORMAL;  /* condition failed, drop out of loop */
      break;
    }
    r = tcl_eval(tcl, tcl_data(body), tcl_length(body) + 1);
    if (r != FCONT && r != FNORMAL) {
      assert(r == FBREAK || r == FRETURN || r == FEXIT || r == FERROR);
      if (r == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
    r = tcl_eval(tcl, tcl_data(post), tcl_length(post) + 1);
    if (r != FNORMAL) {
      break;
    }
  }
  tcl_free(cond);
  tcl_free(post);
  tcl_free(body);
  return r;
}

static int tcl_cmd_foreach(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 4);
  struct tcl_value *name = tcl_list_item(args, 1);
  struct tcl_value *list = tcl_list_item(args, 2);
  struct tcl_value *body = tcl_list_item(args, 3);
  int r = FNORMAL;
  int n = tcl_list_length(list);
  for (int i = 0; i < n; i++) {
    tcl_var(tcl, tcl_data(name), tcl_list_item(list, i));
    r = tcl_eval(tcl, tcl_data(body), tcl_length(body) + 1);
    if (r != FCONT && r != FNORMAL) {
      assert(r == FBREAK || r == FRETURN || r == FEXIT || r == FERROR);
      if (r == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
  }
  tcl_free(name);
  tcl_free(list);
  tcl_free(body);
  return r;
}

static int tcl_cmd_flow(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  int r = FERROR;
  struct tcl_value *flowval = tcl_list_item(args, 0);
  const char *flow = tcl_data(flowval);
  if (strcmp(flow, "break") == 0) {
    r = FBREAK;
  } else if (strcmp(flow, "continue") == 0) {
    r = FCONT;
  } else if (strcmp(flow, "return") == 0) {
    r = tcl_result(tcl, FRETURN,
                   (tcl_list_length(args) == 2) ? tcl_list_item(args, 1) : tcl_value("", 0));
  } else if (strcmp(flow, "exit") == 0) {
    r = tcl_result(tcl, FEXIT,
                   (tcl_list_length(args) == 2) ? tcl_list_item(args, 1) : tcl_value("", 0));
  }
  tcl_free(flowval);
  return r;
}

/* -------------------------------------------------------------------------- */

enum {
  TOK_END_EXPR = 0,
  TOK_NUMBER = 256,
  TOK_VARIABLE,
  TOK_OR,           /* || */
  TOK_AND,          /* && */
  TOK_EQ,           /* == */
  TOK_NE,           /* != */
  TOK_GE,           /* >= */
  TOK_LE,           /* <= */
  TOK_SHL,          /* << */
  TOK_SHR,          /* >> */
  TOK_EXP,          /* ** */
};

enum {
  eNONE = 0,        /* no error */
  eNUM_EXPECT,      /* number expected */
  eINVALID_NUM,     /* invalid number syntax */
  ePARENTHESES,     /* unbalanced parentheses */
  eEXTRA_CHARS,     /* extra characters after expression (missing operator?) */
  eINVALID_CHAR,
  eDIV0,            /* divide by zero */
};

struct expr {
  const char *pos;  /* current position in expression */
  int token;        /* current token */
  int lexflag;
  tcl_int lnumber;  /* literal value */
  int error;
  struct tcl *tcl;  /* for variable lookup */
};

static tcl_int expr_conditional(struct expr *expr);
#define lex(e)          ((e)->lexflag ? ((e)->lexflag = 0, (e)->token) : expr_lex(e) )
#define unlex(e)        ((e)->lexflag = 1)

static void expr_error(struct expr *expr, int number) {
  if (expr->error == eNONE)
    expr->error = number;
  assert(expr->pos != NULL);
  while (*expr->pos != '\0')
    expr->pos += 1; /* skip rest of string, to forcibly end parsing */
}

static void expr_skip(struct expr *expr, int number) {
  while (*expr->pos != '\0' && number-- > 0)
    expr->pos++;
  while (*expr->pos != '\0' && *expr->pos <= ' ')
    expr->pos++;
}

static int expr_lex(struct expr *expr) {
  static const char special[] = "?:|&^~<>=!-+*/%(){}";

  assert(expr && expr->pos);
  if (*expr->pos == '\0') {
    expr->token = TOK_END_EXPR;
    return expr->token;
  }

  if (strchr(special, *expr->pos) != NULL) {
    expr->token = (int)*expr->pos;
    expr->pos += 1; /* don't skip whitespace yet, first check for multi-character operators */
    switch (expr->token) {
    case '|':
      if (*expr->pos == '|') {
        expr->token = TOK_OR;
        expr->pos += 1;
      }
      break;
    case '&':
      if (*expr->pos == '&') {
        expr->token = TOK_AND;
        expr->pos += 1;
      }
      break;
    case '=':
      if (*expr->pos == '=') {
        expr->token = TOK_EQ;
        expr->pos += 1;
      }
      break;
    case '!':
      if (*expr->pos == '=') {
        expr->token = TOK_NE;
        expr->pos += 1;
      }
      break;
    case '<':
      if (*expr->pos == '=') {
        expr->token = TOK_LE;
        expr->pos += 1;
      } else if (*expr->pos == '<') {
        expr->token = TOK_SHL;
        expr->pos += 1;
      }
      break;
    case '>':
      if (*expr->pos == '=') {
        expr->token = TOK_GE;
        expr->pos += 1;
      } else if (*expr->pos == '>') {
        expr->token = TOK_SHR;
        expr->pos += 1;
      }
      break;
    case '*':
      if (*expr->pos == '*') {
        expr->token = TOK_EXP;
        expr->pos += 1;
      }
      break;
    }
    expr_skip(expr, 0);          /* erase white space */
  } else if (tcl_isdigit(*expr->pos)) {
    char *ptr;
    expr->token = TOK_NUMBER;
    expr->lnumber = strtol(expr->pos, &ptr, 0);
    expr->pos = ptr;
    if (tcl_isalpha(*expr->pos) || *expr->pos == '.' || *expr->pos == ',')
      expr_error(expr, eINVALID_NUM);
    expr_skip(expr, 0);          /* erase white space */
  } else if (*expr->pos == '$') {
    char name[MAX_VAR_LENGTH] = "";
    bool quote = (*(expr->pos + 1) == '{');
    char close = quote ? '}' : '\0';
    expr->pos += 1;   /* skip '$' */
    if (quote) {
      expr->pos += 1; /* skip '{' */
    }
    int i = 0;
    while (i < sizeof(name) - 1 && *expr->pos != close && *expr->pos != '(' && *expr->pos != ')'
           && (quote || !tcl_is_space(*expr->pos))  && !tcl_is_operator(*expr->pos)
           && !tcl_is_special(*expr->pos, false)) {
      name[i++] = *expr->pos++;
    }
    name[i] = '\0';
    if (quote && *expr->pos == close) {
      expr->pos += 1; /* skip '}' */
    }
    if (*expr->pos == '(') {
      expr_skip(expr, 1);
      tcl_int v = expr_conditional(expr);
      if (lex(expr) != ')')
        expr_error(expr, ePARENTHESES);
      strlcat(name, "(", sizeof name);
      char buf[64];
      strlcat(name, tcl_int2string(buf, sizeof buf, 10, v), sizeof name);
      strlcat(name, ")", sizeof name);
    }
    expr_skip(expr, 0);          /* erase white space */
    const struct tcl_value *varvalue = tcl_var(expr->tcl, name, NULL);
    expr->token = TOK_VARIABLE;
    expr->lnumber = varvalue ? strtol(tcl_data(varvalue), NULL, 10) : 0;
  } else {
    expr_error(expr, eINVALID_CHAR);
    expr->token = TOK_END_EXPR;
  }
  return expr->token;
}

static tcl_int expr_primary(struct expr *expr) {
  tcl_int v = 0;
  int tok_close = 0;
  switch (lex(expr)) {
  case '-':
    v = -expr_primary(expr);
    break;
  case '+':
    v = -expr_primary(expr);
    break;
  case '!':
    v = !expr_primary(expr);
    break;
  case '~':
    v = ~expr_primary(expr);
    break;
  case '(':
  case '{':
    tok_close = (expr->token == '(') ? ')' : '}';
    v = expr_conditional(expr);
    if (lex(expr) != tok_close)
      expr_error(expr, ePARENTHESES);
    break;
  case TOK_VARIABLE:
  case TOK_NUMBER:
    v = expr->lnumber;
    break;
  default:
    expr_error(expr, eNUM_EXPECT);
  }
  return v;
}

static tcl_int expr_power(struct expr *expr) {
  tcl_int v1 = expr_primary(expr);
  while (lex(expr) == TOK_EXP) {
    tcl_int v2 = expr_power(expr); /* right-to-left associativity */
    if (v2 < 0) {
      v1 = 0;
    } else {
      tcl_int n = v1;
      v1 = 1;
      while (v2--)
        v1 *= n;
    }
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_product(struct expr *expr) {
  tcl_int v1 = expr_power(expr);
  int op;
  while ((op = lex(expr)) == '*' || op == '/' || op == '%') {
    tcl_int v2 = expr_power(expr);
    if (op == '*') {
      v1 *= v2;
    } else {
      if (v2 != 0L) {
        tcl_int div = v1 / v2;
        tcl_int rem = v1 % v2;
        /* ensure floored division, with positive remainder */
        if (rem < 0) {
          div -= 1;
          rem += v1;
        }
        v1 = (op == '/') ? div : rem;
      } else {
        expr_error(expr, eDIV0);
      }
    }
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_sum(struct expr *expr) {
  tcl_int v1 = expr_product(expr);
  int op;
  while ((op = lex(expr)) == '+' || op == '-') {
    tcl_int v2 = expr_product(expr);
    if (op == '+')
      v1 += v2;
    else
      v1 -= v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_shift(struct expr *expr) {
  tcl_int v1 = expr_sum(expr);
  int op;
  while ((op = lex(expr)) == TOK_SHL || op == TOK_SHR) {
    tcl_int v2 = expr_sum(expr);
    if (op == TOK_SHL)
      v1 = (v1 << v2);
    else
      v1 = (v1 >> v2);
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_relational(struct expr *expr) {
  tcl_int v1 = expr_shift(expr);
  int op;
  while ((op = lex(expr)) == '<' || op == '>' || op == TOK_LE || op == TOK_GE) {
    tcl_int v2 = expr_shift(expr);
    switch (op) {
    case '<':
      v1 = (v1 < v2);
      break;
    case '>':
      v1 = (v1 > v2);
      break;
    case TOK_LE:
      v1 = (v1 <= v2);
      break;
    case TOK_GE:
      v1 = (v1 >= v2);
      break;
    }
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_equality(struct expr *expr) {
  tcl_int v1 = expr_relational(expr);
  int op;
  while ((op = lex(expr)) == TOK_EQ || op == TOK_NE) {
    tcl_int v2 = expr_relational(expr);
    if (op == TOK_EQ)
      v1 = (v1 == v2);
    else
      v1 = (v1 != v2);
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_binary_and(struct expr *expr) {
  tcl_int v1 = expr_equality(expr);
  while (lex(expr) == '&') {
    tcl_int v2 = expr_equality(expr);
    v1 = v1 & v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_binary_xor(struct expr *expr) {
  tcl_int v1 = expr_binary_and(expr);
  while (lex(expr) == '^') {
    tcl_int v2 = expr_binary_and(expr);
    v1 = v1 ^ v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_binary_or(struct expr *expr) {
  tcl_int v1 = expr_binary_xor(expr);
  while (lex(expr) == '|') {
    tcl_int v2 = expr_binary_xor(expr);
    v1 = v1 | v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_logic_and(struct expr *expr) {
  tcl_int v1 = expr_binary_or(expr);
  while (lex(expr) == TOK_AND) {
    tcl_int v2 = expr_binary_or(expr);
    v1 = v1 && v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_logic_or(struct expr *expr) {
  tcl_int v1 = expr_logic_and(expr);
  while (lex(expr) == TOK_OR) {
    tcl_int v2 = expr_logic_and(expr);
    v1 = v1 || v2;
  }
  unlex(expr);
  return v1;
}

static tcl_int expr_conditional(struct expr *expr) {
  tcl_int v1 = expr_logic_or(expr);
  if (lex(expr) == '?') {
    tcl_int v2 = expr_conditional(expr);
    if (lex(expr) != ':')
      expr_error(expr, eINVALID_CHAR);
    tcl_int v3 = expr_logic_or(expr);
    v1 = v1 ? v2 : v3;
  }
  unlex(expr);
  return v1;
}

static int tcl_expression(struct tcl *tcl, const char *expression, tcl_int *result) {
  struct expr expr;
  memset(&expr, 0, sizeof(expr));
  expr.pos = expression;
  expr.tcl = tcl;
  expr_skip(&expr, 0);            /* erase leading white space */
  *result = expr_conditional(&expr);
  expr_skip(&expr, 0);            /* erase trailing white space */
  if (expr.error == eNONE) {
    int op = lex(&expr);
    if (op == ')')
      expr_error(&expr, ePARENTHESES);
    else if (op != TOK_END_EXPR)
      expr_error(&expr, eEXTRA_CHARS);
  }
  return expr.error;
}

static char *tcl_int2string(char *buffer, size_t bufsz, int radix, tcl_int value) {
  assert(buffer);
  assert(radix == 10 || radix == 16);
  char *p = buffer + bufsz - 1;
  *p-- = '\0';
  if (radix == 16) {
    do {
      unsigned char c = (value & 0xf);
      *p-- = (c < 10) ? '0' + c : 'A' + (c - 10);
      value = value >> 4;
    } while (value > 0);
  } else {
    bool neg = (value < 0);
    if (neg) {
      value = -value;
    }
    do {
      *p-- = '0' + (value % 10);
      value = value / 10;
    } while (value > 0);
    if (neg) {
      *p-- = '-';
    }
  }
  return p + 1;
}

static int tcl_cmd_expr(struct tcl *tcl, struct tcl_value *args, void *arg) {
  (void)arg;
  /* re-construct the expression (it may have been tokenized by the Tcl Lexer) */
  struct tcl_value *expression;
  int count = tcl_list_length(args);
  if (count == 2) {
    expression = tcl_list_item(args, 1);
  } else {
    size_t size = tcl_length(args);
    assert(strncmp(tcl_data(args), "expr", 4) == 0);
    expression = tcl_value(tcl_data(args) + 4, size - 4);  /* "expr" is 4 characters */
  }
  int r = FNORMAL;
  /* nested square brackets must be evaluated before proceeding with the expression */
  for (;;) {
    const char *open = tcl_data(expression);
    while (*open != '\0' && *open != '[') {
      open++;
    }
    if (*open != '[') {
      break;
    }
    const char *close = open + 1;
    int depth = 1;
    while (*close != '\0') {
      if (*close == ']') {
        if (--depth == 0) {
          break;
        }
      } else if (*close == '[') {
        depth++;
      }
      close++;
    }
    if (depth == 0) {
      assert(*close == ']');
      /* split the expression string up in 3 blocks, evaluate the middle part */
      struct tcl_value *prefix = tcl_value(tcl_data(expression), open - tcl_data(expression));
      struct tcl_value *suffix = tcl_value(close + 1, tcl_length(expression) - ((close + 1) - tcl_data(expression)));
      r = tcl_eval(tcl, open + 1, close - open - 1);
      /* build the new expression */
      tcl_free(expression);
      expression = prefix;
      tcl_append(expression, tcl_dup(tcl->result));
      tcl_append(expression, suffix);
    }
  }
  /* parse expression */
  tcl_int result;
  int err = tcl_expression(tcl, tcl_data(expression), &result);
  if (err == eNONE) {
    r = tcl_numeric_result(tcl, r, result);
  } else {
    r = tcl_error_result(tcl, TCLERR_EXPR, tcl_data(expression));
  }
  tcl_free(expression);

  /* convert result to string & store */
  return r;
}

/* -------------------------------------------------------------------------- */

void tcl_init(struct tcl *tcl) {
  init_ctype();
  assert(tcl);
  memset(tcl, 0, sizeof(struct tcl));
  tcl->env = tcl_env_alloc(NULL);
  tcl->result = tcl_value("", 0);

  /* built-in commands */
  tcl_register(tcl, "append", tcl_cmd_append, 3, 0, NULL);
  tcl_register(tcl, "array", tcl_cmd_array, 3, 5, NULL);
  tcl_register(tcl, "break", tcl_cmd_flow, 1, 1, NULL);
  tcl_register(tcl, "concat", tcl_cmd_concat, 1, 0, NULL);
  tcl_register(tcl, "continue", tcl_cmd_flow, 1, 1, NULL);
  tcl_register(tcl, "exit", tcl_cmd_flow, 1, 2, NULL);
  tcl_register(tcl, "expr", tcl_cmd_expr, 1, 0, NULL);
  tcl_register(tcl, "for", tcl_cmd_for, 5, 5, NULL);
  tcl_register(tcl, "foreach", tcl_cmd_foreach, 4, 4, NULL);
  tcl_register(tcl, "format", tcl_cmd_format, 2, 0, NULL);
  tcl_register(tcl, "global", tcl_cmd_global, 2, 0, NULL);
  tcl_register(tcl, "if", tcl_cmd_if, 3, 0, NULL);
  tcl_register(tcl, "incr", tcl_cmd_incr, 2, 3, NULL);
  tcl_register(tcl, "info", tcl_cmd_info, 2, 3, NULL);
  tcl_register(tcl, "join", tcl_cmd_join, 2, 3, NULL);
  tcl_register(tcl, "lappend", tcl_cmd_lappend, 3, 0, NULL);
  tcl_register(tcl, "list", tcl_cmd_list, 1, 0, NULL);
  tcl_register(tcl, "lindex", tcl_cmd_lindex, 3, 3, NULL);
  tcl_register(tcl, "llength", tcl_cmd_llength, 2, 2, NULL);
  tcl_register(tcl, "lrange", tcl_cmd_lrange, 4, 4, NULL);
  tcl_register(tcl, "lreplace", tcl_cmd_lreplace, 4, 0, NULL);
  tcl_register(tcl, "proc", tcl_cmd_proc, 4, 4, NULL);
  tcl_register(tcl, "return", tcl_cmd_flow, 1, 2, NULL);
  tcl_register(tcl, "scan", tcl_cmd_scan, 3, 0, NULL);
  tcl_register(tcl, "set", tcl_cmd_set, 2, 3, NULL);
  tcl_register(tcl, "split", tcl_cmd_split, 2, 3, NULL);
  tcl_register(tcl, "string", tcl_cmd_string, 3, 6, NULL);
  tcl_register(tcl, "subst", tcl_cmd_subst, 2, 2, NULL);
  tcl_register(tcl, "switch", tcl_cmd_switch, 3, 0, NULL);
  tcl_register(tcl, "unset", tcl_cmd_unset, 2, 0, NULL);
  tcl_register(tcl, "upvar", tcl_cmd_upvar, 2, 0, NULL);
  tcl_register(tcl, "while", tcl_cmd_while, 3, 3, NULL);
# if !defined TCL_DISABLE_CLOCK
    tcl_register(tcl, "clock", tcl_cmd_clock, 2, 4, NULL);
# endif
# if !defined TCL_DISABLE_FILEIO
    tcl_register(tcl, "close", tcl_cmd_close, 2, 2, NULL);
    tcl_register(tcl, "eof", tcl_cmd_eof, 2, 2, NULL);
    tcl_register(tcl, "file", tcl_cmd_file, 3, 3, NULL);
    tcl_register(tcl, "gets", tcl_cmd_gets, 2, 3, NULL);
    tcl_register(tcl, "open", tcl_cmd_open, 2, 3, NULL);
    tcl_register(tcl, "puts", tcl_cmd_puts, 2, 3, NULL);
    tcl_register(tcl, "read", tcl_cmd_read, 2, 3, NULL);
    tcl_register(tcl, "seek", tcl_cmd_seek, 3, 4, NULL);
    tcl_register(tcl, "tell", tcl_cmd_tell, 2, 2, NULL);
# elif !defined TCL_DISABLE_PUTS
    tcl_register(tcl, "puts", tcl_cmd_puts, 2, 2, NULL);
# endif
# if !defined TCL_DISABLE_BINARY
    tcl_register(tcl, "binary", tcl_cmd_binary, 4, 0, NULL);
# endif
}

void tcl_destroy(struct tcl *tcl) {
  assert(tcl);
  while (tcl->env) {
    tcl->env = tcl_env_free(tcl->env);
  }
  while (tcl->cmds) {
    struct tcl_cmd *cmd = tcl->cmds;
    tcl->cmds = tcl->cmds->next;
    tcl_free(cmd->name);
    if (cmd->fn == tcl_user_proc) {
      tcl_free((struct tcl_value*)cmd->user);
    }
    free(cmd);
  }
  tcl_free(tcl->result);
  if (tcl->errinfo) {
    tcl_free(tcl->errinfo);
  }
  memset(tcl, 0, sizeof(struct tcl));
}

struct tcl_value *tcl_return(struct tcl *tcl) {
  assert(tcl);
  return (tcl->result);
}

const char *tcl_errorinfo(struct tcl *tcl, int *code, const char **info, int *line) {
  static const char *msg[] = {
    /* TCLERR_UNKNOWN */    "no error",
    /* TCLERR_GENERAL */    "unspecified error",
    /* TCLERR_MEMORY */     "memory allocation failure",
    /* TCLERR_SYNTAX */     "general syntax error",
    /* TCLERR_BRACES */     "unbalanced curly braces",
    /* TCLERR_EXPR */       "invalid expression",
    /* TCLERR_CMDUNKNOWN */ "unknown command",
    /* TCLERR_CMDARGCOUNT */"wrong argument count on command",
    /* TCLERR_SUBCMD */     "unknown command option",
    /* TCLERR_VARUNKNOWN */ "unknown variable name",
    /* TCLERR_NAMEINVALID */"invalid symbol name (variable or command)",
    /* TCLERR_NAMEEXISTS */ "duplicate symbol name (symbol already defined)",
    /* TCLERR_ARGUMENT */   "incorrect (or missing) argument to a command",
    /* TCLERR_DEFAULTARG */ "incorrect default value on parameter",
    /* TCLERR_SCOPE */      "invalid scope (or command not valid at current scope)",
    /* TCLERR_FILEIO */     "operation on file failed",
    /* TCLERR_USER */       "user error",
  };
  assert(tcl);

  int errcode = 0;
  struct tcl_var *var = tcl_findvar(tcl->env, "errorCode");
  if (var) {
    errcode = strtol(tcl_data(var->value[0]), NULL, 10);
    if (var->env) {
      assert(var->env != tcl->env);
      struct tcl_var *ref_var = tcl_findvar(var->env, tcl_data(var->name));
      tcl_var_free(var->env, ref_var);
    }
    tcl_var_free(tcl->env, var);
  }
  assert(errcode >= 0 && errcode < sizeof(msg)/sizeof(msg[0]));
  if (errcode < 0 || errcode >= sizeof(msg)/sizeof(msg[0])) {
    errcode = 1;  /* protect against scripts setting errorCode */
  }

  if (code) {
    *code = errcode;
  }
  if (info) {
    *info = "";
    var = tcl_findvar(tcl->env, "errorInfo");
    if (var) {
      if (tcl->errinfo) {
        tcl_free(tcl->errinfo);
      }
      tcl->errinfo = tcl_dup(var->value[0]);  /* copy, because variable is erased */
      *info = tcl_data(tcl->errinfo);
      if (var->env) {
        assert(var->env != tcl->env);
        struct tcl_var *ref_var = tcl_findvar(var->env, tcl_data(var->name));
        tcl_var_free(var->env, ref_var);
      }
      tcl_var_free(tcl->env, var);
    }
  }

  struct tcl_env *global_env = tcl_env_scope(tcl, 0);
  if (line) {
    *line = 0;
    const char *script = global_env->errinfo.codebase;
    assert(script);
    if (script) {
      *line = 1;
      while (script < global_env->errinfo.currentpos) {
        if (*script == '\r' || *script == '\n') {
          *line += 1;
          if (*script == '\r' && *(script + 1) == '\n') {
            script++; /* handle \r\n as a single line feed */
          }
        }
        script++;
      }
    }
  }

  return msg[errcode];
}

