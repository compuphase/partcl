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
#include "fortify.h"
#include "tcl.h"


#define MAX_VAR_LENGTH  256
#define BIN_TOKEN       '\x01'
#define BIN_SIZE(s)     (*(unsigned short*)((unsigned char*)(s)+1))

/* Token type and control flow constants */
enum { TERROR, TCMD, TWORD, TPART };
enum { FERROR, FNORMAL, FRETURN, FBREAK, FAGAIN, FEXIT };

#define MARKFLOW(f, e)  ((f) | ((e) << 8))
#define FLOW(r)         ((r) & 0xff)
#define FLOW_NORMAL(r)  (((r) & 0xff) == FNORMAL)

/* Lexer flags & options */
#define LEX_QUOTE   0x01  /* inside a double-quote section */
#define LEX_VAR     0x02  /* special mode for parsing variable names */
#define LEX_NO_CMT  0x04  /* don't allow comment here (so comment is allowed when this is not set) */

static bool tcl_is_operator(char c) {
  return (c == '|' || c == '&' || c == '~' || c == '<' || c == '>' ||
          c == '=' || c == '!' || c == '-' || c == '+' || c == '*' ||
          c == '/' || c == '%' || c == '?' || c == ':');
}
static bool tcl_is_special(char c, bool quote, bool isvar) {
  return (c == '[' || c == ']' || c == '"' || c == '\0' ||
          (!isvar && c == '$') ||
          (!quote && (c == '{' || c == '}' || c == ';' || c == '\r' || c == '\n')) );
}

static bool tcl_is_space(char c) { return (c == ' ' || c == '\t'); }

static bool tcl_is_end(char c) {
  return (c == '\n' || c == '\r' || c == ';' || c == '\0');
}

static int tcl_next(const char *string, size_t length, const char **from, const char **to,
                    unsigned *flags) {
  unsigned int i = 0;
  int depth = 0;
  bool quote = ((*flags & LEX_QUOTE) != 0);

  /* Skip leading spaces if not quoted */
  for (; !quote && length > 0 && tcl_is_space(*string); string++, length--)
    {}
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
    return TCMD;
  }

  if (*string == '$') { /* Variable token, must not start with a space or quote */
    if (tcl_is_space(string[1]) || string[1] == '"' || (*flags & LEX_VAR)) {
      return TERROR;
    }
    unsigned saved_flags = *flags;
    *flags = (*flags & ~LEX_QUOTE) | LEX_VAR; /* quoting is off, variable name parsing is on */
    int r = tcl_next(string + 1, length - 1, to, to, flags);
    *flags = saved_flags;
    return ((r == TWORD && quote) ? TPART : r);
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
      } else if (string[i] == BIN_TOKEN && i+3 < length) {
        /* skip the binary block */
        unsigned n = BIN_SIZE(string + i);
        if (i + n + 2 < length) {
          i += n + 2; /* 1 less because there is an i++ in the for loop */
        }
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
    return TWORD;
  } else if (*string == ']' || *string == '}') {
    return TERROR;    /* Unbalanced bracket or brace */
  } else if (*string == BIN_TOKEN) {
    i = BIN_SIZE(string) + 3;
    if (i >= length) {
      return TERROR;
    }
  } else {
    bool isvar = ((*flags & LEX_VAR) != 0);
    while (i < length &&                                /* run until string completed... */
           (quote || !tcl_is_space(string[i])) &&       /* ... and no whitespace (unless quoted) ... */
           !(isvar && tcl_is_operator(string[i])) &&    /* ... and no operator in variable mode ... */
           !tcl_is_special(string[i], quote, isvar)) {  /* ... and no special characters (where "special" depends on quote status) */
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
  return (tcl_is_space(string[i]) || tcl_is_end(string[i])) ? TWORD : TPART;
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

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

int tcl_type(const tcl_value_t *v) {
  if (!v) {
    return TCLTYPE_EMPTY;
  }
  if (*v == BIN_TOKEN) {
    return TCLTYPE_BLOB;
  }

  /* try to parse number */
  const char *p = v;
  while (tcl_is_space(*p)) { p++; } /* allow leading whitespace */
  if (*p == '-') { p++; }           /* allow minus sign before the number */
  if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X') ) {
    p += 2; /* hex. number */
    while (isxdigit(*p)) { p++; }
  } else {
    while (isdigit(*p)) { p++; }
  }
  while (tcl_is_space(*p)) { p++; } /* allow trailing whitespace */
  if (*p == '\0') {
    return TCLTYPE_INT; /* successfully parsed an integer format */
  }

  /* everything else: string */
  return TCLTYPE_STRING;
}

const char *tcl_string(const tcl_value_t *v) {
  return (*v == BIN_TOKEN) ? v + 3 : v;
}

size_t tcl_length(const tcl_value_t *v) {
  if (!v) {
    return 0;
  }
  if (*v == BIN_TOKEN) {
    return BIN_SIZE(v);
  }
  return strlen(v);
}

long tcl_int(const tcl_value_t *v) {
  if (tcl_type(v) == TCLTYPE_INT) {
    return strtol(v, NULL, 0);
  }
  return 0;
}

tcl_value_t *tcl_free(tcl_value_t *v) {
  assert(v);
  free(v);
  return NULL;
}

static bool tcl_binary(const void *blob, size_t len) { /* blob can be a tcl_value_t or byte array */
  if (!len) {
    return false;   /* empty block, don't care */
  }
  assert(blob);
  const unsigned char *p = blob;
  if (*p == BIN_TOKEN) {
    return true;    /* block is already binary, keep it binary */
  }
  while (len--) {
    if (!*p++) {
      return true;  /* zero-byte found, this must be a binary blob */
    }
  }
  return false;     /* checks passed, can store as text */
}

static tcl_value_t *tcl_append_string(tcl_value_t *v, const char *data, size_t len, bool binary) {
  size_t n = tcl_length(v);
  size_t prefix = (binary || tcl_binary(v, n) || tcl_binary(data, len)) ? 3 : 0;
  size_t sz = n + len;
  char *b = malloc(sz + prefix + 1); /* allocate 1 byte extra, so that malloc() won't fail if n + len == 0 */
  if (b) {
    if (prefix) {
      *b = '\x01';
      unsigned short *u = (unsigned short*)(b + 1);
      *u = (unsigned short)sz;
    }
    if (n > 0) {
      assert(v);
      memcpy(b + prefix, tcl_string(v), n);
    }
    memcpy(b + prefix + n, data, len);
    b[prefix + n + len] = 0;           /* set extra byte that was allocated to 0 */
    if (v) {
      free(v);
    }
    v = b;
  }
  return v;
}

tcl_value_t *tcl_append(tcl_value_t *value, tcl_value_t *tail) {
  assert(tail);
  size_t tlen = tcl_length(tail);
  value = tcl_append_string(value, tcl_string(tail), tlen, tcl_binary(tail, tlen));
  tcl_free(tail);
  return value;
}

tcl_value_t *tcl_value(const char *data, size_t len, bool binary) {
  return tcl_append_string(NULL, data, len, binary);
}

static tcl_value_t *tcl_dup(const tcl_value_t *value) {
  assert(value);
  size_t vlen = tcl_length(value);
  return tcl_value(tcl_string(value), vlen, tcl_binary(value, vlen));
}

tcl_value_t *tcl_list_new(void) {
  return tcl_value("", 0, false);
}

#define tcl_list_free(v) tcl_free(v)

int tcl_list_length(tcl_value_t *list) {  /* returns the number of items in the list */
  int count = 0;
  tcl_each(tcl_string(list), tcl_length(list) + 1, 0) {
    if (p.token == TWORD) {
      count++;
    }
  }
  return count;
}

static size_t tcl_list_size(tcl_value_t *list) { /* returns the size in bytes of the list (excluding the final zero) */
  if (!list) {
    return 0;
  }
  const char *p = list;
  while (*p) {
    if (*p == BIN_TOKEN) {
      p += BIN_SIZE(p) + 3;
    } else {
      p++;
    }
  }
  return (p - list);
}

static bool tcl_list_item_ptr(tcl_value_t *list, int index, const char **data, size_t *size) {
  int i = 0;
  tcl_each(tcl_string(list), tcl_length(list) + 1, 0) {
    if (p.token == TWORD) {
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

tcl_value_t *tcl_list_item(tcl_value_t *list, int index) {
  const char *data;
  size_t sz;
  if (tcl_list_item_ptr(list, index, &data, &sz))
    return tcl_value(data, sz, tcl_binary(data, sz));
  return NULL;
}

tcl_value_t *tcl_list_append(tcl_value_t *list, tcl_value_t *tail) {
  /* calculate required memory */
  size_t listsz = tcl_list_size(list);
  bool separator = (listsz > 0);
  bool quote = false;
  size_t extrasz = separator ? 1 : 0;
  int taillen = tcl_length(tail);
  extrasz += taillen;
  if (taillen > 0) {
    if (tcl_binary(tail, taillen)) {
      extrasz += 3;
      quote = true; /* always quote binary blobs */
    } else {
      for (const char *p = tcl_string(tail); *p && !quote; p++) {
        if (tcl_is_space(*p) || tcl_is_special(*p, false, false)) {
          quote = true;
        }
      }
    }
  } else {
    quote = true; /* quote, to create an empty element */
  }
  if (quote) {
    extrasz += 2;
  }
  /* allocate & copy */
  char *newlist = malloc(listsz + extrasz + 1);
  if (!newlist) {
    return NULL;
  }
  char *tgt = newlist;
  if (listsz > 0) {
    memcpy(tgt, list, listsz);
    tgt += listsz;
  }
  if (separator) {
    memcpy(tgt, " ", 1);
    tgt += 1;
  }
  if (quote) {
    memcpy(tgt, "{", 1);
    tgt += 1;
  }
  if (taillen > 0) {
    int hdr = tcl_binary(tail, taillen) ? 3 : 0;
    memcpy(tgt, tail, taillen + hdr);
    tgt += taillen + hdr;
  }
  if (quote) {
    memcpy(tgt, "}", 1);
    tgt += 1;
  }
  *tgt = '\0';
  tcl_free(tail);
  tcl_list_free(list);
  return newlist;
}

/* ----------------------------- */
/* ----------------------------- */
/* ----------------------------- */
/* ----------------------------- */

static char *tcl_int2string(char *buffer, size_t bufsz, int radix, long value);
static int tcl_error_result(struct tcl *tcl, int flow);
static int tcl_var_index(const char *name, size_t *baselength);

struct tcl_cmd {
  tcl_value_t *name;      /**< function name */
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
  short errorcode;        /**< the error code */
};

struct tcl_var {
  tcl_value_t *name;
  tcl_value_t **value;    /**< array of values */
  int elements;           /**< for an array, the number of "values" allocated */
  bool global;            /**< this is an alias for a global variable */
  struct tcl_var *next;
};

struct tcl_env {
  struct tcl_var *vars;
  struct tcl_env *parent;
  struct tcl_errinfo errinfo;
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
    var->name = tcl_value(name, namesz, false);
    var->elements = 1;
    var->value = malloc(var->elements * sizeof(tcl_value_t*));
    if (var->value) {
      var->value[0] = tcl_value("", 0, false);
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
    free(var);
  }
  free(env);
  return parent;
}

static struct tcl_env *tcl_global_env(struct tcl *tcl) {
  struct tcl_env *global_env = tcl->env;
  while (global_env->parent) {
    global_env = global_env->parent;
  }
  return global_env;
}

static int tcl_var_index(const char *name, size_t *baselength) {
  size_t len = strlen(name);
  const char *ptr = name + len;
  int idx = 0;
  if (ptr > name && *(ptr - 1) == ')') {
    ptr--;
    while (ptr > name && isdigit(*(ptr - 1))) {
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
    const char *varptr = tcl_string(var->name);
    size_t varsz;
    tcl_var_index(var->name, &varsz);
    if (varsz == namesz && strncmp(varptr, name, varsz) == 0) {
      return var;
    }
  }
  return NULL;
}

const tcl_value_t *tcl_var(struct tcl *tcl, const char *name, tcl_value_t *value) {
  struct tcl_var *var = tcl_findvar(tcl->env, name);
  if (var && var->global) { /* found local alias of a global variable; find the global */
    var = tcl_findvar(tcl_global_env(tcl), name);
  }
  if (!var) {
    if (!value) { /* value being read before being set */
      tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_VARUNKNOWN));
    }
    var = tcl_env_var(tcl->env, name);
  }
  int idx = tcl_var_index(name, NULL);
  if (var->elements <= idx) {
    size_t newsize = var->elements;
    while (newsize <= idx) {
      newsize *= 2;
    }
    tcl_value_t **newlist = malloc(newsize * sizeof(tcl_value_t*));
    if (newlist) {
      memset(newlist, 0, newsize * sizeof(tcl_value_t*));
      memcpy(newlist, var->value, var->elements * sizeof(tcl_value_t*));
      free(var->value);
      var->value = newlist;
      var->elements = newsize;
    } else {
      tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_MEMORY));
      idx = 0;  /* sets/returns wrong index, but avoid accessing out of range index */
    }
  }
  if (value) {
    if (var->value[idx]) {
      tcl_free(var->value[idx]);
    }
    var->value[idx] = value;
  } else if (var->value[idx] == NULL) {
    var->value[idx] = tcl_value("", 0, false);
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
    if (pred) {
      pred->next = var->next;
    }
  }
  /* then delete */
  tcl_free(var->name);
  assert(var->value);
  for (int idx = 0; idx < var->elements; idx++) {
    if (var->value[idx]) {
      tcl_free(var->value[idx]);
    }
  }
  free(var->value);
  free(var);
}

int tcl_result(struct tcl *tcl, int flow, tcl_value_t *result) {
  tcl_free(tcl->result);
  tcl->result = result;
  if (FLOW(flow) == FERROR && tcl->env->errinfo.errorcode == 0) {
    tcl->env->errinfo.errorcode = flow >> 8;
  }
  return FLOW(flow);
}

static int tcl_int_result(struct tcl *tcl, int flow, long result) {
  char buf[64] = "";
  char *ptr = tcl_int2string(buf, sizeof(buf), 10, result);
  return tcl_result(tcl, flow, tcl_value(ptr, strlen(ptr), false));
}

static int tcl_error_result(struct tcl *tcl, int flow) {
  /* helper function for a common case */
  return tcl_result(tcl, flow, tcl_value("", 0, false));
}

static int tcl_subst(struct tcl *tcl, const char *s, size_t len) {
  if (len == 0) {
    return tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
  }
  switch (s[0]) {
  case '{':
    if (len <= 1) {
      return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_SYNTAX));
    }
    return tcl_result(tcl, FNORMAL, tcl_value(s + 1, len - 2, tcl_binary(s + 1, len - 2)));
  case '$': {
    if (len >= MAX_VAR_LENGTH) {
      return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_VARNAME));
    }
    tcl_value_t *name = tcl_value(s + 1, len - 1, false);
    /* check for a variable index (arrays) */
    const char *start;
    for (start = tcl_string(name); *start != '\0' && *start != '('; start++)
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
        int baselen = start - tcl_string(name);
        tcl_subst(tcl, start, end - start);
        tcl_free(name);
        name = tcl_value(s + 1, baselen, false);  /* includes opening '(' */
        name = tcl_append(name, tcl_dup(tcl->result));
        name = tcl_append(name, tcl_value(")", 1, false));
      }
    }
    int r = tcl_result(tcl, FNORMAL, tcl_dup(tcl_var(tcl, tcl_string(name), NULL)));
    tcl_free(name);
    return r;
  }
  case '[': {
    tcl_value_t *expr = tcl_value(s + 1, len - 2, tcl_binary(s + 1, len - 2));
    int r = tcl_eval(tcl, tcl_string(expr), tcl_length(expr) + 1);
    tcl_free(expr);
    return FLOW(r);
  }
  default:
    return tcl_result(tcl, FNORMAL, tcl_value(s, len, tcl_binary(s, len)));
  }
}

static struct tcl_cmd *tcl_lookup_cmd(struct tcl *tcl, tcl_value_t *name, unsigned numargs) {
  assert(name);
  assert(numargs > 0);
  for (struct tcl_cmd *cmd = tcl->cmds; cmd != NULL; cmd = cmd->next) {
    if (strcmp(tcl_string(name), tcl_string(cmd->name)) == 0 &&
        (cmd->minargs <= numargs && numargs <= cmd->maxargs)) {
      return cmd;
    }
  }
  return NULL;
}

static int tcl_exec_cmd(struct tcl *tcl, tcl_value_t *list) {
  tcl_value_t *cmdname = tcl_list_item(list, 0);
  struct tcl_cmd *cmd = tcl_lookup_cmd(tcl, cmdname, tcl_list_length(list));
  tcl_free(cmdname);
  if (!cmd) {
    return MARKFLOW(FERROR, TCLERR_CMDUNKNOWN);
  }
  return cmd->fn(tcl, list, cmd->user);
}

int tcl_eval(struct tcl *tcl, const char *string, size_t length) {
  if (!tcl->env->errinfo.codebase) {
    tcl->env->errinfo.codebase = string;
    tcl->env->errinfo.codesize = length;
  }
  tcl_value_t *list = tcl_list_new();
  tcl_value_t *cur = NULL;
  int result = FNORMAL;
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
      result = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_SYNTAX));
      break;
    case TWORD:
      result = tcl_subst(tcl, p.from, p.to - p.from);
      if (cur) {
        tcl_value_t *part = tcl_dup(tcl->result);
        cur = tcl_append(cur, part);
      } else {
        cur = tcl_dup(tcl->result);
      }
      list = tcl_list_append(list, cur);
      cur = NULL;
      break;
    case TPART:
      result = tcl_subst(tcl, p.from, p.to - p.from);
      tcl_value_t *part = tcl_dup(tcl->result);
      cur = tcl_append(cur, part);
      break;
    case TCMD:
      if (tcl_list_length(list) > 0) {
        result = tcl_exec_cmd(tcl, list);
        tcl_list_free(list);
        list = tcl_list_new();
      } else {
        result = FNORMAL;
      }
      markposition = true;
      break;
    }
    if (!FLOW_NORMAL(result)) {
      if (FLOW(result) == FERROR) {
        tcl_error_result(tcl, result);
      }
      break;
    }
  }
  /* when arrived at the end of the buffer, if the list is non-empty, run that
     last command */
  if (FLOW_NORMAL(result) && tcl_list_length(list) > 0) {
    if (cur) {
      list = tcl_list_append(list, cur);
    }
    result = tcl_exec_cmd(tcl, list);
  }
  tcl_list_free(list);
  return (tcl->env->errinfo.errorcode > 0) ? FERROR : FLOW(result);
}

/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */

static int tcl_expression(struct tcl *tcl, const char *expression, long *result);  /* forward declaration */

struct tcl_cmd *tcl_register(struct tcl *tcl, const char *name, tcl_cmd_fn_t fn,
                             unsigned short minargs, unsigned short maxargs,
                             void *user) {
  struct tcl_cmd *cmd = malloc(sizeof(struct tcl_cmd));
  if (cmd) {
    memset(cmd, 0, sizeof(struct tcl_cmd));
    cmd->name = tcl_value(name, strlen(name), false);
    cmd->fn = fn;
    cmd->user = user;
    cmd->minargs = minargs;
    cmd->maxargs = (maxargs == 0) ? USHRT_MAX : maxargs;
    cmd->next = tcl->cmds;
    tcl->cmds = cmd;
  }
  return cmd;
}

static int tcl_cmd_set(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *name = tcl_list_item(args, 1);
  assert(name);
  tcl_value_t *val = tcl_list_item(args, 2);
  int r = tcl_result(tcl, FNORMAL, tcl_dup(tcl_var(tcl, tcl_string(name), val)));
  tcl_free(name);
  return r;
}

static int tcl_cmd_unset(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    tcl_value_t *name = tcl_list_item(args, 1);
    assert(name);
    struct tcl_var *var = tcl_findvar(tcl->env, name);
    if (var) {
      if (var->global) {
        assert(tcl->env->parent); /* globals can only be declared at local scope */
        struct tcl_env *global_env = tcl_global_env(tcl);
        struct tcl_var *global_var = tcl_findvar(global_env, name);
        tcl_var_free(global_env, global_var);
      }
      tcl_var_free(tcl->env, var);
    }
    tcl_free(name);
  }
  return tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
}

static int tcl_cmd_global(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  if (!tcl->env->parent) {
    return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_SCOPE));
  }
  int r = FNORMAL;
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    tcl_value_t *name = tcl_list_item(args, i);
    assert(name);
    struct tcl_var *var;
    if ((var = tcl_findvar(tcl->env, name)) != NULL) {
      /* name exists locally, cannot create an alias with the same name */
      r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_VARNAME));
    } else if (tcl_findvar(tcl_global_env(tcl), name) == NULL) {
      /* name not known as a global */
      r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_VARUNKNOWN));
    } else {
      /* make local, find it back, mark it as an alias for a global */
      tcl_var(tcl, tcl_string(name), tcl_value("", 0, false));  /* make local */
      if ((var = tcl_findvar(tcl->env, name)) != NULL) {
        var->global = true;
      }
    }
    tcl_free(name);
  }
  return r;
}

static int tcl_cmd_subst(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *s = tcl_list_item(args, 1);
  int r = tcl_subst(tcl, tcl_string(s), tcl_length(s));
  tcl_free(s);
  return r;
}

static int tcl_cmd_scan(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *string = tcl_list_item(args, 1);
  tcl_value_t *format = tcl_list_item(args, 2);
  assert(string && format);
  int match = 0;
  const char *sptr = tcl_string(string);
  const char *fptr = tcl_string(format);
  while (*fptr) {
    if (*fptr == '%') {
      fptr++; /* skip '%' */
      char buf[32] = "";
      if (isdigit(*fptr)) {
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
      tcl_value_t *var = tcl_list_item(args, match + 2);
      if (var) {
        char buf[64];
        char *p = tcl_int2string(buf, sizeof buf, 10, v);
        tcl_var(tcl, tcl_string(var), tcl_value(p, strlen(p), false));
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
  return tcl_int_result(tcl, FNORMAL, match);
}

static int tcl_cmd_format(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  size_t bufsize = 256;
  char *buffer = malloc(bufsize);
  if (!buffer) {
    return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_MEMORY));
  }
  tcl_value_t *format = tcl_list_item(args, 1);
  assert(format);
  const char *fptr = tcl_string(format);
  size_t buflen = 0;
  int index = 2;
  tcl_value_t *argcopy = NULL;
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
      if (isdigit(*fptr)) {
        bool zeropad = (*fptr == '0');
        pad = (int)strtol(fptr, (char**)&fptr, 10);
        if (pad <= 0 || pad > sizeof(field) - 1) {
          pad = 0;
        } else {
          memset(field, zeropad ? '0' : ' ', sizeof(field));
        }
      }
      char ival[32];
      char *pval;
      int skip = 0;
      argcopy = tcl_list_item(args, index++);
      switch (*fptr) {
      case 'c':
        fieldlen = (pad > 1) ? pad : 1;
        skip = left_justify ? 0 : fieldlen - 1;
        field[skip] = (char)tcl_int(argcopy);
        break;
      case 'd':
      case 'i':
      case 'x':
        pval = tcl_int2string(ival, sizeof(ival), (*fptr == 'x') ? 16 : 10, tcl_int(argcopy));
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
        memcpy(buffer + buflen + skip, tcl_string(argcopy), slen);
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
  int r = tcl_result(tcl, FNORMAL, tcl_value(buffer, buflen, false));
  free(buffer);
  return r;
}

static int tcl_cmd_incr(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int val = 1;
  if (tcl_list_length(args) == 3) {
    tcl_value_t *incr = tcl_list_item(args, 2);
    val = tcl_int(incr);
    tcl_free(incr);
  }
  tcl_value_t *name = tcl_list_item(args, 1);
  assert(name);
  char buf[64];
  char *p = tcl_int2string(buf, sizeof buf, 10, tcl_int(tcl_var(tcl, tcl_string(name), NULL)) + val);
  tcl_var(tcl, tcl_string(name), tcl_value(p, strlen(p), false));
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, tcl_value(p, strlen(p), false));
}

static int tcl_cmd_append(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  tcl_value_t *name = tcl_list_item(args, 1);
  assert(name);
  tcl_value_t *val = tcl_dup(tcl_var(tcl, tcl_string(name), NULL));
  for (int i = 2; i < nargs; i++) {
    tcl_value_t *tail = tcl_list_item(args, i);
    val = tcl_append(val, tail);
  }
  tcl_var(tcl, tcl_string(name), tcl_dup(val));
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, val);
}

#define SUBCMD(v, s)  (strcmp(tcl_string(v), (s)) == 0)

/* source: https://stackoverflow.com/a/23457543 */
static bool tcl_match(const char *pattern, const char *candidate, int p, int c) {
  if (pattern[p] == '\0') {
    return candidate[c] == '\0';
  } else if (pattern[p] == '*') {
    for (; candidate[c] != '\0'; c++) {
      if (tcl_match(pattern, candidate, p+1, c))
        return true;
    }
    return tcl_match(pattern, candidate, p+1, c);
  } else if (pattern[p] != '?' && pattern[p] != candidate[c]) {
    return false;
  }  else {
    return tcl_match(pattern, candidate, p+1, c+1);
  }
}

static int tcl_cmd_string(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  int r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
  tcl_value_t *subcmd = tcl_list_item(args, 1);
  tcl_value_t *arg1 = tcl_list_item(args, 2);
  if (SUBCMD(subcmd, "length")) {
    r = tcl_int_result(tcl, FNORMAL, tcl_length(arg1));
  } else if (SUBCMD(subcmd, "tolower") || SUBCMD(subcmd, "toupper")) {
    bool lcase = SUBCMD(subcmd, "tolower");
    tcl_value_t *tgt = tcl_dup(arg1);
    size_t sz = tcl_length(tgt);
    char *base = (char*)tcl_string(tgt);
    for (size_t i = 0; i < sz; i++) {
      base[i] = lcase ? tolower(base[i]) : toupper(base[i]);
    }
  } else if (SUBCMD(subcmd, "trim") || SUBCMD(subcmd, "trimleft") || SUBCMD(subcmd, "trimright")) {
    const char *chars = " \t\r\n";
    tcl_value_t *arg2 = NULL;
    if (nargs >= 4) {
      tcl_value_t *arg2 = tcl_list_item(args, 3);
      chars = tcl_string(arg2);
    }
    const char *first = tcl_string(arg1);
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
    r = tcl_result(tcl, FNORMAL, tcl_value(first, last - first, false));
    if (arg2) {
      tcl_free(arg2);
    }
  } else {
    if (nargs < 4) {  /* need at least "string subcommand arg arg" */
      tcl_free(subcmd);
      tcl_free(arg1);
      return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
    }
    tcl_value_t *arg2 = tcl_list_item(args, 3);
    if (SUBCMD(subcmd, "compare")) {
      r = tcl_int_result(tcl, FNORMAL, strcmp(tcl_string(arg1), tcl_string(arg2)));
    } else if (SUBCMD(subcmd, "equal")) {
      r = tcl_int_result(tcl, FNORMAL, strcmp(tcl_string(arg1), tcl_string(arg2)) == 0);
    } else if (SUBCMD(subcmd, "first") || SUBCMD(subcmd, "last")) {
      int pos = 0;
      if (nargs >= 5) {
        tcl_value_t *arg3 = tcl_list_item(args, 4);
        pos = tcl_int(arg3);
        tcl_free(arg3);
      }
      const char *haystack = tcl_string(arg2);
      const char *needle = tcl_string(arg1);
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
      r = tcl_int_result(tcl, FNORMAL, (p && p >= haystack) ? (p - haystack) : -1);
    } else if (SUBCMD(subcmd, "index")) {
      int pos = tcl_int(arg2);
      if (pos >= tcl_length(arg1)) {
        r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
      } else {
        r = tcl_result(tcl, FNORMAL, tcl_value(tcl_string(arg1) + pos, 1, false));
      }
    } else if (SUBCMD(subcmd, "match")) {
      if (tcl_length(arg1) == 0 || (tcl_length(arg2) == 0 && strcmp(tcl_string(arg1), "*") != 0)) {
        r = tcl_int_result(tcl, FNORMAL, 0);
      } else {
        r = tcl_int_result(tcl, FNORMAL, tcl_match(tcl_string(arg1), tcl_string(arg2), 0, 0));
      }
    } else if (SUBCMD(subcmd, "range")) {
      int first = tcl_int(arg2);
      if (first < 0) {
        first = 0;
      }
      int last = INT_MAX;
      if (nargs >= 5) {
        tcl_value_t *arg3 = tcl_list_item(args, 4);
        if (strcmp(tcl_string(arg3), "end") != 0) {
          last = tcl_int(arg3);
        }
        tcl_free(arg3);
      }
      if (last > tcl_length(arg1)) {
        last = tcl_length(arg1);
      }
      r = tcl_result(tcl, FNORMAL, tcl_value(tcl_string(arg1) + first, last - first + 1, false));
    } else if (SUBCMD(subcmd, "replace")) {
      if (nargs < 6) {  /* need at least "string replace text idx1 idx2 word" */
        tcl_free(subcmd);
        tcl_free(arg1);
        tcl_free(arg2);
        return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
      }
      size_t len = tcl_length(arg1);
      int idx1 = tcl_int(arg2);
      if (idx1 < 0 || idx1 >= len) {
        idx1 = 0;
      }
      tcl_value_t *arg3 = tcl_list_item(args, 4);
      int idx2 = tcl_int(arg3);
      if (idx2 < 0 || idx2 >= len) {
        idx2 = len - 1;
      }
      tcl_value_t *modified = tcl_value(arg1, idx1, false);
      modified = tcl_append(modified, tcl_dup(tcl_list_item(args, 5)));
      modified = tcl_append(modified, tcl_value(tcl_string(arg1) + idx2 + 1, tcl_length(arg1) - (idx2 + 1), false));
      tcl_free(arg3);
    }
    if (arg2) {
      tcl_free(arg2);
    }
  }
  tcl_free(subcmd);
  tcl_free(arg1);
  return r;
}

static int tcl_cmd_info(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  tcl_value_t *subcmd = tcl_list_item(args, 1);
  int r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
  if (SUBCMD(subcmd, "exists")) {
    if (nargs >= 3) {
      tcl_value_t *name = tcl_list_item(args, 2);
      r = tcl_int_result(tcl, FNORMAL, (tcl_findvar(tcl->env, name) != NULL));
      tcl_free(name);
    }
  } else if (SUBCMD(subcmd, "tclversion")) {
    r = tcl_result(tcl, FNORMAL, tcl_value("1.0", 3, false));
  }
  tcl_free(subcmd);
  return r;
}

static int tcl_cmd_array(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  tcl_value_t *subcmd = tcl_list_item(args, 1);
  tcl_value_t *name = tcl_list_item(args, 2);
  int r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
  if (SUBCMD(subcmd, "length") || SUBCMD(subcmd, "size")) {
    struct tcl_var *var = tcl_findvar(tcl->env, tcl_string(name));
    if (var && var->global) { /* found local alias of a global variable; find the global */
      var = tcl_findvar(tcl_global_env(tcl), tcl_string(name));
    }
    int count = 0;
    if (var) {
      for (int i = 0; i < var->elements; i++) {
        if (var->value[i]) {
          count++;
        }
      }
    }
    r = tcl_int_result(tcl, FNORMAL, count);
  } else if (SUBCMD(subcmd, "slice")) {
    if (nargs < 4) {  /* need at least "array slice var blob" */
      tcl_free(subcmd);
      tcl_free(name);
      return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
    }
    tcl_value_t *blob = tcl_list_item(args, 3);
    const unsigned char *bptr = tcl_string(blob);
    size_t blen = tcl_length(blob);
    tcl_value_t *wsize = (nargs > 4) ? tcl_list_item(args, 4) : NULL;
    int step = wsize ? tcl_int(wsize) : 1;
    if (step < 1) {
      step = 1;
    }
    int count = 0;
    struct tcl_var *var = NULL;
    while (blen > 0) {
      /* make value (depending on step size) and convert to string */
      long value = 0;
      for (int i = 0; i < step && i < blen; i++) {
        value |= (long)*(bptr + i) << 8 * i;
      }
      char buf[64];
      char *p = tcl_int2string(buf, sizeof buf, 10, value);
      if (!var) {
        /* make the variable (implicitly sets index 0), find it back */
        tcl_var(tcl, tcl_string(name), tcl_value(p, strlen(p), false));
        var = tcl_findvar(tcl->env, tcl_string(name));
        assert(var);            /* if it didn't yet exist, it was just created */
        if (var->global) {      /* found local alias of a global variable; find the global */
          var = tcl_findvar(tcl_global_env(tcl), tcl_string(name));
        }
        /* can immediately allocate the properly sized value list */
        int numelements = blen / step + 1;
        tcl_value_t **newlist = malloc(numelements * sizeof(tcl_value_t*));
        if (newlist) {
          memset(newlist, 0, numelements * sizeof(tcl_value_t*));
          assert(var->elements == 1);
          newlist[0] = var->value[0];
          free(var->value);
          var->value = newlist;
          var->elements = numelements;
        } else {
          tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_MEMORY));
          count = 0;
          break;
        }
      } else {
        assert(count < var->elements);
        var->value[count] = tcl_value(p, strlen(p), false);
      }
      count++;
      bptr += step;
      blen = (blen > step) ? blen - step : 0;
    }
    tcl_free(blob);
    if (wsize) {
      tcl_free(wsize);
    }
    r = tcl_int_result(tcl, (count > 0) ? FNORMAL : FERROR, count);
  } else {
    r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
  }
  tcl_free(subcmd);
  tcl_free(name);
  return r;
}

static int tcl_cmd_list(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_new();
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    list = tcl_list_append(list, tcl_list_item(args, i));
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_concat(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_new();
  int n = tcl_list_length(args);
  for (int i = 1; i < n; i++) {
    tcl_value_t *sublst = tcl_list_item(args, i);
    int sublst_len = tcl_list_length(sublst);
    for (int j = 0; j < sublst_len; j++) {
      list = tcl_list_append(list, tcl_list_item(sublst, j));
    }
    tcl_free(sublst);
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_lappend(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int n = tcl_list_length(args);
  tcl_value_t *list = tcl_list_new();
  /* check whether the value exists */
  tcl_value_t *name = tcl_list_item(args, 1);
  struct tcl_var *var = tcl_findvar(tcl->env, tcl_string(name));
  if (var && var->global) { /* found local alias of a global variable; find the global */
    var = tcl_findvar(tcl_global_env(tcl), tcl_string(name));
  }
  if (var) {
    /* variable exists, collect the items already in it */
    tcl_value_t *v_list = tcl_dup(tcl_var(tcl, tcl_string(name), NULL));
    int v_len = tcl_list_length(v_list);
    for (int i = 0; i < v_len; i++) {
      list = tcl_list_append(list, tcl_list_item(v_list, i));
    }
    tcl_free(v_list);
  }
  /* append other arguments, update the variable */
  for (int i = 2; i < n; i++) {
    list = tcl_list_append(list, tcl_list_item(args, i));
  }
  tcl_var(tcl, tcl_string(name), tcl_dup(list));
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_lreplace(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  tcl_value_t *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  tcl_value_t *v_first = tcl_list_item(args, 2);
  int first = tcl_int(v_first);
  tcl_free(v_first);
  tcl_value_t *v_last = tcl_list_item(args, 3);
  int last = (strcmp(tcl_string(v_last), "end") == 0) ? list_len - 1 : tcl_int(v_last);
  tcl_free(v_last);
  tcl_value_t *rangelist = tcl_list_new();
  /* copy up to "first" elements from the original list */
  for (int i = 0; i < first; i++) {
    rangelist = tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  /* append arguments after the lreplace command */
  for (int i = 4; i < nargs; i++) {
    rangelist = tcl_list_append(rangelist, tcl_list_item(args, i));
  }
  /* copy the items behind "last" from the original list */
  for (int i = last + 1; i < list_len; i++) {
    rangelist = tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  tcl_free(list);
  return tcl_result(tcl, FNORMAL, rangelist);
}

static int tcl_cmd_llength(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_item(args, 1);
  int n = tcl_list_length(list);
  tcl_free(list);
  return tcl_int_result(tcl, FNORMAL, n);
}

static int tcl_cmd_lindex(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_item(args, 1);
  tcl_value_t *v_index = tcl_list_item(args, 2);
  int index = tcl_int(v_index);
  tcl_free(v_index);
  int n = tcl_list_length(list);
  int r = FNORMAL;
  if (index < n) {
    r = tcl_result(tcl, FNORMAL, tcl_list_item(list, index));
  } else {
    r = tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
  }
  tcl_free(list);
  return r;
}

static int tcl_cmd_lrange(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  tcl_value_t *v_first = tcl_list_item(args, 2);
  int first = tcl_int(v_first);
  tcl_free(v_first);
  tcl_value_t *v_last = tcl_list_item(args, 3);
  int last = (strcmp(tcl_string(v_last), "end") == 0) ? list_len - 1 : tcl_int(v_last);
  tcl_free(v_last);
  tcl_value_t *rangelist = tcl_list_new();
  for (int i = first; i <= last; i++) {
    rangelist = tcl_list_append(rangelist, tcl_list_item(list, i));
  }
  tcl_free(list);
  return tcl_result(tcl, FNORMAL, rangelist);
}

static int tcl_cmd_split(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *v_string = tcl_list_item(args, 1);
  const char *string = tcl_string(v_string);
  size_t string_len = tcl_length(v_string);
  tcl_value_t *v_sep = (tcl_list_length(args) > 2) ? tcl_list_item(args, 2) : NULL;
  const char *chars = v_sep ? tcl_string(v_sep) : " \t\r\n";
  tcl_value_t *list = tcl_list_new();
  const char *start = string;
  const char *end = start;
  while (end - string < string_len) {
    assert(*end);
    if (strchr(chars, *end)) {
      list = tcl_list_append(list, tcl_value(start, end - start, false));
      start = end + 1;
    }
    end++;
  }
  /* append last item */
  list = tcl_list_append(list, tcl_value(start, end - start, false));
  tcl_free(v_string);
  if (v_sep) {
    tcl_free(v_sep);
  }
  return tcl_result(tcl, FNORMAL, list);
}

static int tcl_cmd_join(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *list = tcl_list_item(args, 1);
  int list_len = tcl_list_length(list);
  tcl_value_t *sep = (tcl_list_length(args) >= 3) ? tcl_list_item(args, 2) : tcl_value(" ", 1, false);
  tcl_value_t *string = NULL;
  for (int i = 0; i < list_len; i++) {
    string = tcl_append(string, tcl_list_item(list, i));
    if (i + 1 < list_len && tcl_length(sep) > 0) {
      string = tcl_append(string, tcl_dup(sep));
    }
  }
  tcl_free(list);
  tcl_free(sep);
  return tcl_result(tcl, FNORMAL, string);
}

#ifndef TCL_DISABLE_PUTS
static int tcl_cmd_puts(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *text = tcl_list_item(args, 1);
  puts(tcl_string(text));
  return tcl_result(tcl, FNORMAL, text);
}
#endif

static int tcl_user_proc(struct tcl *tcl, tcl_value_t *args, void *arg) {
  tcl_value_t *code = (tcl_value_t *)arg;
  tcl_value_t *params = tcl_list_item(code, 2);
  tcl_value_t *body = tcl_list_item(code, 3);
  tcl->env = tcl_env_alloc(tcl->env);
  for (int i = 0; i < tcl_list_length(params); i++) {
    tcl_value_t *param = tcl_list_item(params, i);
    tcl_value_t *v = tcl_list_item(args, i + 1);
    tcl_var(tcl, tcl_string(param), v);
    tcl_free(param);
  }
  int r = tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
  if (FLOW(r) == FERROR || tcl->env->errinfo.errorcode != 0) {
    size_t error_offs = tcl->env->errinfo.currentpos - tcl->env->errinfo.codebase;
    /* need to calculate the offset of the body relative to the start of the
       proc declaration */
    const char *body_ptr;
    size_t body_sz;
    tcl_list_item_ptr(code, 3, &body_ptr, &body_sz);
    error_offs += body_ptr - code;
    /* need to find the proc again */
    tcl_value_t *cmdname = tcl_list_item(code, 1);
    struct tcl_cmd *cmd = tcl_lookup_cmd(tcl, cmdname, 0);
    tcl_free(cmdname);
    assert(cmd);  /* it just ran, so it must be found */
    struct tcl_env *global_env = tcl_global_env(tcl);
    global_env->errinfo.errorcode = tcl->env->errinfo.errorcode;
    global_env->errinfo.currentpos = cmd->declpos + error_offs;
  }
  tcl->env = tcl_env_free(tcl->env);
  tcl_free(params);
  tcl_free(body);
  return r;
}

static int tcl_cmd_proc(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *name = tcl_list_item(args, 1);
  tcl_value_t *arglist = tcl_list_item(args, 2);
  unsigned argcount = tcl_list_length(arglist);
  struct tcl_cmd *cmd = tcl_register(tcl, tcl_string(name), tcl_user_proc, argcount, argcount, tcl_dup(args));
  tcl_free(name);
  tcl_free(arglist);
  struct tcl_env *global_env = tcl_global_env(tcl);
  cmd->declpos = global_env->errinfo.currentpos;
  return tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
}

static tcl_value_t *tcl_make_condition_list(tcl_value_t *cond) {
  tcl_value_t *list = tcl_list_new();
  list = tcl_list_append(list, tcl_value("expr", 4, false));
  list = tcl_list_append(list, cond);
  return list;
}

static int tcl_cmd_if(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int i = 1;
  int n = tcl_list_length(args);
  int r = tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
  while (i < n) {
    tcl_value_t *cond = tcl_make_condition_list(tcl_list_item(args, i++));
    tcl_value_t *branch = (i < n) ? tcl_list_item(args, i++) : NULL;
    if (strcmp(tcl_string(branch), "then") == 0) {
      tcl_free(branch); /* ignore optional keyword "then", get next branch */
      branch = (i < n) ? tcl_list_item(args, i++) : NULL;
    }
    r = tcl_eval(tcl, tcl_string(cond), tcl_length(cond) + 1);
    cond = tcl_list_free(cond);
    if (!FLOW_NORMAL(r)) {
      tcl_free(branch);   /* error in condition expression, abort */
      break;
    } else if (!branch) {
      return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
    }
    if (tcl_int(tcl->result)) {
      r = tcl_eval(tcl, tcl_string(branch), tcl_length(branch) + 1);
      tcl_free(branch);
      break;              /* branch taken, do not take any other branch */
    }
    branch = tcl_free(branch);
    /* "then" branch not taken, check how to continue, first check for keyword */
    if (i < n) {
      branch = tcl_list_item(args, i);
      if (strcmp(tcl_string(branch), "elseif") == 0) {
        branch = tcl_free(branch);
        i++;              /* skip the keyword (then drop back into the loop,
                             parsing the next condition) */
      } else if (strcmp(tcl_string(branch), "else") == 0) {
        branch = tcl_free(branch);
        i++;              /* skip the keyword */
        if (i < n) {
          branch = tcl_list_item(args, i++);
          r = tcl_eval(tcl, tcl_string(branch), tcl_length(branch) + 1);
          tcl_free(branch);
          break;          /* "else" branch taken, do not take any other branch */
        } else {
          return tcl_error_result(tcl, MARKFLOW(FERROR, TCLERR_PARAM));
        }
      } else if (i + 1 < n) {
        /* no explicit keyword, but at least two blocks in the list:
           assume it is {cond} {branch} (implied elseif) */
        branch = tcl_free(branch);
      } else {
        /* last block: must be (implied) else */
        i++;
        r = tcl_eval(tcl, tcl_string(branch), tcl_length(branch) + 1);
        branch = tcl_free(branch);
      }
    }

  }
  return FLOW(r);
}

static int tcl_cmd_switch(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int nargs = tcl_list_length(args);
  int r = tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
  tcl_value_t *crit = tcl_list_item(args, 1);
  /* there are two forms of switch: all pairs in a list, or all pairs simply
     appended onto the tail of the command */
  tcl_value_t *list;
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
    tcl_value_t *pattern = tcl_list_item(list, list_idx);
    bool match = (strcmp(tcl_string(pattern), "default") != 0 &&
                  !tcl_match(tcl_string(pattern), tcl_string(crit), 0, 0));
    tcl_free(pattern);
    if (match) {
      break;
    }
    list_idx += 2;  /* skip pattern & body pair */
  }
  /* find body */
  tcl_value_t *body = NULL;
  list_idx += 1;
  while (list_idx < list_len) {
    tcl_value_t *body = tcl_list_item(list, list_idx);
    if (strcmp(tcl_string(body), "-") != 0)
      break;
    body = tcl_free(body);
    list_idx += 2;  /* body, plus pattern of the next case */
  }
  /* clean up values that are no longer needed */
  tcl_free(crit);
  if (nargs == 3) {
    tcl_list_free(list);
  }
  /* execute the body */
  if (body) {
    r = tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
    tcl_free(body);
  }
  return r;
}

static int tcl_cmd_while(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 3);
  tcl_value_t *cond = tcl_make_condition_list(tcl_list_item(args, 1));
  tcl_value_t *body = tcl_list_item(args, 2);
  int r = FNORMAL;
  for (;;) {
    r = tcl_eval(tcl, tcl_string(cond), tcl_length(cond) + 1);
    if (!FLOW_NORMAL(r)) {
      break;
    }
    if (!tcl_int(tcl->result)) {
      r = FNORMAL;
      break;
    }
    r = tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
    if (FLOW(r) != FAGAIN && FLOW(r) != FNORMAL) {
      assert(FLOW(r) == FBREAK || FLOW(r) == FRETURN || FLOW(r) == FEXIT || FLOW(r) == FERROR);
      if (FLOW(r) == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
  }
  tcl_list_free(cond);
  tcl_free(body);
  return FLOW(r);
}

static int tcl_cmd_for(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 5);
  tcl_value_t *setup = tcl_list_item(args, 1);
  int r = tcl_eval(tcl, tcl_string(setup), tcl_length(setup) + 1);
  tcl_free(setup);
  if (!FLOW_NORMAL(r)) {
    return FLOW(r);
  }
  tcl_value_t *cond = tcl_make_condition_list(tcl_list_item(args, 2));
  tcl_value_t *post = tcl_list_item(args, 3);
  tcl_value_t *body = tcl_list_item(args, 4);
  for (;;) {
    r = tcl_eval(tcl, tcl_string(cond), tcl_length(cond) + 1);
    if (!FLOW_NORMAL(r)) {
      break;
    }
    if (!tcl_int(tcl->result)) {
      r = FNORMAL;  /* condition failed, drop out of loop */
      break;
    }
    r = tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
    if (FLOW(r) != FAGAIN && FLOW(r) != FNORMAL) {
      assert(FLOW(r) == FBREAK || FLOW(r) == FRETURN || FLOW(r) == FEXIT || FLOW(r) == FERROR);
      if (FLOW(r) == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
    r = tcl_eval(tcl, tcl_string(post), tcl_length(post) + 1);
    if (!FLOW_NORMAL(r)) {
      break;
    }
  }
  tcl_list_free(cond);
  tcl_free(post);
  tcl_free(body);
  return FLOW(r);
}

static int tcl_cmd_foreach(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  assert(tcl_list_length(args) == 4);
  tcl_value_t *name = tcl_list_item(args, 1);
  tcl_value_t *list = tcl_list_item(args, 2);
  tcl_value_t *body = tcl_list_item(args, 3);
  int r = FNORMAL;
  int n = tcl_list_length(list);
  for (int i = 0; i < n; i++) {
    tcl_var(tcl, tcl_string(name), tcl_list_item(list, i));
    r = tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
    if (FLOW(r) != FAGAIN && FLOW(r) != FNORMAL) {
      assert(FLOW(r) == FBREAK || FLOW(r) == FRETURN || FLOW(r) == FEXIT || FLOW(r) == FERROR);
      if (FLOW(r) == FBREAK) {
        r = FNORMAL;
      }
      break;
    }
  }
  tcl_free(name);
  tcl_list_free(list);
  tcl_free(body);
  return FLOW(r);
}

static int tcl_cmd_flow(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int r = FERROR;
  tcl_value_t *flowval = tcl_list_item(args, 0);
  const char *flow = tcl_string(flowval);
  if (strcmp(flow, "break") == 0) {
    r = FBREAK;
  } else if (strcmp(flow, "continue") == 0) {
    r = FAGAIN;
  } else if (strcmp(flow, "return") == 0) {
    r = tcl_result(tcl, FRETURN,
                   (tcl_list_length(args) == 2) ? tcl_list_item(args, 1) : tcl_value("", 0, false));
  } else if (strcmp(flow, "exit") == 0) {
    r = tcl_result(tcl, FEXIT,
                   (tcl_list_length(args) == 2) ? tcl_list_item(args, 1) : tcl_value("", 0, false));
  }
  tcl_free(flowval);
  return r;
}

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

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
  long lnumber;     /* literal value */
  int error;
  struct tcl *tcl;  /* for variable lookup */
};

static long expr_conditional(struct expr *expr);
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
  } else if (isdigit(*expr->pos)) {
    char *ptr;
    expr->token = TOK_NUMBER;
    expr->lnumber = strtol(expr->pos, &ptr, 0);
    expr->pos = ptr;
    if (isalpha(*expr->pos) || *expr->pos == '.' || *expr->pos == ',')
      expr_error(expr, eINVALID_NUM);
    expr_skip(expr, 0);          /* erase white space */
  } else if (*expr->pos == '$') {
    char name[MAX_VAR_LENGTH] = "";
    bool quote = (*expr->pos == '{');
    char close = quote ? '}' : '\0';
    expr->pos += 1;   /* skip '$' */
    if (quote) {
      expr->pos += 1; /* skip '{' */
    }
    int i = 0;
    while (i < sizeof(name) - 1 && *expr->pos != close && *expr->pos != '(' && *expr->pos != ')'
           && (quote || !tcl_is_space(*expr->pos))  && !tcl_is_operator(*expr->pos)
           && !tcl_is_special(*expr->pos, false, false)) {
      name[i++] = *expr->pos++;
    }
    name[i] = '\0';
    if (quote && *expr->pos == close) {
      expr->pos += 1; /* skip '}' */
    }
    if (*expr->pos == '(') {
      expr_skip(expr, 1);
      long v = expr_conditional(expr);
      if (lex(expr) != ')')
        expr_error(expr, ePARENTHESES);
      strcat(name, "(");
      char buf[64];
      strcat(name, tcl_int2string(buf, sizeof buf, 10, v));
      strcat(name, ")");
    }
    expr_skip(expr, 0);          /* erase white space */
    const tcl_value_t *varvalue = tcl_var(expr->tcl, name, NULL);
    expr->token = TOK_VARIABLE;
    expr->lnumber = strtol(tcl_string(varvalue), NULL, 10);
  } else {
    expr_error(expr, eINVALID_CHAR);
    expr->token = TOK_END_EXPR;
  }
  return expr->token;
}

static long expr_primary(struct expr *expr) {
  long v = 0;
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

static long expr_power(struct expr *expr) {
  long v1 = expr_primary(expr);
  while (lex(expr) == TOK_EXP) {
    long v2 = expr_power(expr); /* right-to-left associativity */
    if (v2 < 0) {
      v1 = 0;
    } else {
      long n = v1;
      v1 = 1;
      while (v2--)
        v1 *= n;
    }
  }
  unlex(expr);
  return v1;
}

static long expr_product(struct expr *expr) {
  long v1 = expr_power(expr);
  int op;
  while ((op = lex(expr)) == '*' || op == '/' || op == '%') {
    long v2 = expr_power(expr);
    if (op == '*') {
      v1 *= v2;
    } else {
      if (v2 != 0L) {
        if (op == '/')
          v1 /= v2;
        else
          v1 = v1 % v2;
      } else {
        expr_error(expr, eDIV0);
      }
    }
  }
  unlex(expr);
  return v1;
}

static long expr_sum(struct expr *expr) {
  long v1 = expr_product(expr);
  int op;
  while ((op = lex(expr)) == '+' || op == '-') {
    long v2 = expr_product(expr);
    if (op == '+')
      v1 += v2;
    else
      v1 -= v2;
  }
  unlex(expr);
  return v1;
}

static long expr_shift(struct expr *expr) {
  long v1 = expr_sum(expr);
  int op;
  while ((op = lex(expr)) == TOK_SHL || op == TOK_SHR) {
    long v2 = expr_sum(expr);
    if (op == TOK_SHL)
      v1 = (v1 << v2);
    else
      v1 = (v1 >> v2);
  }
  unlex(expr);
  return v1;
}

static long expr_relational(struct expr *expr) {
  long v1 = expr_shift(expr);
  int op;
  while ((op = lex(expr)) == '<' || op == '>' || op == TOK_LE || op == TOK_GE) {
    long v2 = expr_shift(expr);
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

static long expr_equality(struct expr *expr) {
  long v1 = expr_relational(expr);
  int op;
  while ((op = lex(expr)) == TOK_EQ || op == TOK_NE) {
    long v2 = expr_relational(expr);
    if (op == TOK_EQ)
      v1 = (v1 == v2);
    else
      v1 = (v1 != v2);
  }
  unlex(expr);
  return v1;
}

static long expr_binary_and(struct expr *expr) {
  long v1 = expr_equality(expr);
  while (lex(expr) == '&') {
    long v2 = expr_equality(expr);
    v1 = v1 & v2;
  }
  unlex(expr);
  return v1;
}

static long expr_binary_xor(struct expr *expr) {
  long v1 = expr_binary_and(expr);
  while (lex(expr) == '^') {
    long v2 = expr_binary_and(expr);
    v1 = v1 ^ v2;
  }
  unlex(expr);
  return v1;
}

static long expr_binary_or(struct expr *expr) {
  long v1 = expr_binary_xor(expr);
  while (lex(expr) == '|') {
    long v2 = expr_binary_xor(expr);
    v1 = v1 | v2;
  }
  unlex(expr);
  return v1;
}

static long expr_logic_and(struct expr *expr) {
  long v1 = expr_binary_or(expr);
  while (lex(expr) == TOK_AND) {
    long v2 = expr_binary_or(expr);
    v1 = v1 && v2;
  }
  unlex(expr);
  return v1;
}

static long expr_logic_or(struct expr *expr) {
  long v1 = expr_logic_and(expr);
  while (lex(expr) == TOK_OR) {
    long v2 = expr_logic_and(expr);
    v1 = v1 || v2;
  }
  unlex(expr);
  return v1;
}

static long expr_conditional(struct expr *expr) {
  long v1 = expr_conditional(expr);
  while (lex(expr) == '?') {
    long v2 = expr_conditional(expr);
    if (lex(expr) != ':')
      expr_error(expr, eINVALID_CHAR);
    long v3 = expr_conditional(expr);
    v1 = v1 ? v2 : v3;
  }
  unlex(expr);
  return v1;
}

static int tcl_expression(struct tcl *tcl, const char *expression, long *result)
{
  int op;

  struct expr expr;
  memset(&expr, 0, sizeof(expr));
  expr.pos = expression;
  expr.tcl = tcl;
  expr_skip(&expr, 0);            /* erase leading white space */
  *result = expr_logic_or(&expr);
  expr_skip(&expr, 0);            /* erase trailing white space */
  if (expr.error == eNONE) {
    op = lex(&expr);
    if (op == ')')
      expr_error(&expr, ePARENTHESES);
    else if (op != TOK_END_EXPR)
      expr_error(&expr, eEXTRA_CHARS);
  }
  return expr.error;
}

static char *tcl_int2string(char *buffer, size_t bufsz, int radix, long value) {
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

static int tcl_cmd_expr(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  /* re-construct the expression (it may have been tokenized by the Tcl Lexer) */
  tcl_value_t *expression;
  int count = tcl_list_length(args);
  if (count == 2) {
    expression = tcl_list_item(args, 1);
  } else {
    size_t size = tcl_list_size(args);
    expression = tcl_value(args + 4, size - 4, false);  /* "expr" is 4 characters */
  }
  int r = FNORMAL;
  /* nested square brackets must be evaluated before proceeding with the expression */
  for (;;) {
    const char *open = tcl_string(expression);
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
      tcl_value_t *prefix = tcl_value(tcl_string(expression), open - tcl_string(expression), false);
      tcl_value_t *suffix = tcl_value(close + 1, tcl_length(expression) - ((close + 1) - tcl_string(expression)), false);
      r = tcl_eval(tcl, open + 1, close - open - 1);
      /* build the new expression */
      tcl_free(expression);
      expression = tcl_append(prefix, tcl_dup(tcl->result));
      expression = tcl_append(expression, suffix);
    }
  }
  /* parse expression */
  long result;
  int err = tcl_expression(tcl, expression, &result);
  if (err != eNONE) {
    r = MARKFLOW(FERROR, TCLERR_EXPR);
  }
  tcl_free(expression);

  /* convert result to string & store */
  return tcl_int_result(tcl, r, result);
}

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

void tcl_init(struct tcl *tcl) {
  assert(tcl);
  memset(tcl, 0, sizeof(struct tcl));
  tcl->env = tcl_env_alloc(NULL);
  tcl->result = tcl_value("", 0, false);
  tcl_register(tcl, "append", tcl_cmd_append, 3, 0, NULL);
  tcl_register(tcl, "array", tcl_cmd_array, 3, 5, NULL);
  tcl_register(tcl, "break", tcl_cmd_flow, 1, 1, NULL);
  tcl_register(tcl, "concat", tcl_cmd_concat, 1, 2, NULL);
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
  tcl_register(tcl, "while", tcl_cmd_while, 3, 3, NULL);
#ifndef TCL_DISABLE_PUTS
  tcl_register(tcl, "puts", tcl_cmd_puts, 2, 2, NULL);
#endif
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
    free(cmd->user);
    free(cmd);
  }
  tcl_free(tcl->result);
  memset(tcl, 0, sizeof(struct tcl));
}

const char *tcl_errorinfo(struct tcl *tcl, int *code, int *line, int *column) {
  static const char *msg[] = {
    /* TCLERR_GENERAL */    "unspecified error",
    /* TCLERR_SYNTAX */     "syntax error, e.g. unbalanced brackets",
    /* TCLERR_MEMORY */     "memory allocation error",
    /* TCLERR_EXPR */       "error in expression",
    /* TCLERR_CMDUNKNOWN */ "unknown command (mismatch in name or argument count)",
    /* TCLERR_VARUNKNOWN */ "unknown variable name",
    /* TCLERR_VARNAME */    "invalid variable name (e.g. too long)",
    /* TCLERR_PARAM */      "incorrect (or missing) parameter to a command",
    /* TCLERR_SCOPE */      "scope error (e.g. command is allowed in local scope only)",
  };
  assert(tcl);
  assert(code);
  assert(line);
  assert(column);
  struct tcl_env *global_env = tcl_global_env(tcl);
  *code = global_env->errinfo.errorcode;
  *line = 1;
  const char *script = global_env->errinfo.codebase;
  const char *linebase = script;
  while (script < global_env->errinfo.currentpos) {
    if (*script == '\r' || *script == '\n') {
      *line += 1;
      linebase = script + 1;
      if (*script == '\r' && *(script + 1) == '\n') {
        script++; /* handle \r\n as a single line feed */
      }
    }
    script++;
  }
  *column = global_env->errinfo.currentpos - linebase + 1;
  assert(global_env->errinfo.errorcode >= 0 && global_env->errinfo.errorcode < sizeof(msg)/sizeof(msg[0]));
  return msg[global_env->errinfo.errorcode];
}

