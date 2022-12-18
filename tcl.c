/*
The MIT License (MIT)

Copyright (c) 2016 Serge Zaitsev

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcl.h"

#if 0
#define DBG printf
#else
#define DBG(...)
#endif

#define MAX_VAR_LENGTH  256
#define BIN_TOKEN       '\x01'
#define BIN_SIZE(s)     (*(unsigned short*)((s)+1))

/* Token type and control flow constants */
enum { TERROR, TCMD, TWORD, TPART };
enum { FERROR, FNORMAL, FRETURN, FBREAK, FAGAIN };

static bool tcl_is_operator(char c) {
  return (c == '|' || c == '&' || c == '~' || c == '<' || c == '>' ||
          c == '=' || c == '!' || c == '-' || c == '+' || c == '*' ||
          c == '/' || c == '%' || c == '(' || c == ')');
}
static bool tcl_is_special(char c, int q) {
  return (c == '$' || c == '[' || c == ']' || c == '"' || c == '\0' ||
          (!q && (c == '{' || c == '}' || c == ';' || c == '\r' || c == '\n')) );
}

static bool tcl_is_space(char c) { return (c == ' ' || c == '\t'); }

static bool tcl_is_end(char c) {
  return (c == '\n' || c == '\r' || c == ';' || c == '\0');
}

static int tcl_next(const char *list, size_t length, const char **from, const char **to,
                    bool *quote, bool variable) {
  unsigned int i = 0;
  int depth = 0;

  DBG("tcl_next(%.*s)+%d+%d|%d\n", length, list, *from - list, *to - list, *quote);

  /* Skip leading spaces if not quoted */
  for (; !*quote && length > 0 && tcl_is_space(*list); list++, length--)
    {}
  *from = list;
  /* Terminate command if not quoted */
  if (!*quote && length > 0 && tcl_is_end(*list)) {
    *to = list + 1;
    return TCMD;
  }
  if (*list == '$') { /* Variable token, must not start with a space or quote */
    if (tcl_is_space(list[1]) || list[1] == '"') {
      return TERROR;
    }
    int mode = *quote;
    *quote = 0;
    int r = tcl_next(list + 1, length - 1, to, to, quote, true);
    *quote = mode;
    return ((r == TWORD && *quote) ? TPART : r);
  }

  if (*list == '[' || (!*quote && *list == '{')) {
    /* Interleaving pairs are not welcome, but it simplifies the code */
    char open = *list;
    char close = (open == '[' ? ']' : '}');
    for (i = 1, depth = 1; i < length && depth != 0; i++) {
      if (list[i] == '\\' && i+1 < length && (list[i+1] == open || list[i+1] == close)) {
        i++;  /* escaped brace/bracket, skip both '\' and the character that follows it */
      } else if (list[i] == open) {
        depth++;
      } else if (list[i] == close) {
        depth--;
      } else if (list[i] == BIN_TOKEN && i+3 < length) {
        /* skip the binary block */
        unsigned n = BIN_SIZE(list + i);
        if (i + n + 2 < length) {
          i += n + 2;
        }
      }
    }
  } else if (*list == '"') {
    *quote = !*quote;
    *from = *to = list + 1;
    if (*quote) {
      return TPART;
    }
    if (length < 2 || (!tcl_is_space(list[1]) && !tcl_is_end(list[1]))) {
      return TERROR;
    }
    *from = *to = list + 1;
    return TWORD;
  } else if (*list == ']' || *list == '}') {
    return TERROR;    /* Unbalanced bracket or brace */
  } else if (*list == BIN_TOKEN) {
    i = BIN_SIZE(list) + 3;
    if (i >= length) {
      return TERROR;
    }
  } else {
    while (i < length &&                              /* run until string completed... */
           (*quote || !tcl_is_space(list[i])) &&      /* ... and no whitespace (unless quoted) ... */
           !(variable && tcl_is_operator(list[i])) && /* ... and no operator in variable mode ... */
           !tcl_is_special(list[i], *quote)) {        /* ... and no special characters (where "special" depends on quote status) */
      i++;
    }
  }
  *to = list + i;
  if (i > length || (i == length && depth)) {
    return TERROR;
  }
  if (*quote) {
    return TPART;
  }
  return (tcl_is_space(list[i]) || tcl_is_end(list[i])) ? TWORD : TPART;
}

/* A helper parser struct and macro (requires C99) */
struct tcl_parser {
  const char *from;
  const char *to;
  const char *start;
  const char *end;
  bool quote;
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
                             &p.quote, false)) != TERROR) ||                   \
        (skiperr));                                                            \
       p.start = p.to)

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

const char *tcl_string(tcl_value_t *v) {
  return (*v == BIN_TOKEN) ? v + 3 : v;
}
size_t tcl_length(tcl_value_t *v) {
  if (!v) {
    return 0;
  }
  if (*v == BIN_TOKEN) {
    return BIN_SIZE(v);
  }
  return strlen(v);
}
long tcl_int(tcl_value_t *v) {
  long r = 0;
  if (v) {
    char *end;
    r = strtol(v, &end, 0);
    while (tcl_is_space(*end))  /* check that the contents is a valid integer */
      end++;
    if (*end != '\0')
      r = 0;
  }
  return r;
}

void tcl_free(tcl_value_t *v) {
  assert(v);
  free(v);
}

bool tcl_binary(const void *blob, size_t len) { /* blob can be a tcl_value_t or byte array */
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

tcl_value_t *tcl_append_string(tcl_value_t *v, const char *data, size_t len, bool binary) {
  size_t n = tcl_length(v);
  size_t prefix = (binary || tcl_binary(v, n) || tcl_binary(data, len)) ? 3 : 0;
  size_t sz = n + len;
  char* b = malloc(sz + prefix + 1); /* allocate 1 byte extra, so that malloc() won't fail if n + len == 0 */
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

tcl_value_t *tcl_append(tcl_value_t *v, tcl_value_t *tail) {
  assert(tail);
  size_t tlen = tcl_length(tail);
  v = tcl_append_string(v, tcl_string(tail), tlen, tcl_binary(tail, tlen));
  tcl_free(tail);
  return v;
}

tcl_value_t *tcl_value(const char *data, size_t len, bool binary) {
  return tcl_append_string(NULL, data, len, binary);
}

tcl_value_t *tcl_dup(tcl_value_t *value) {
  assert(value);
  size_t vlen = tcl_length(value);
  return tcl_value(tcl_string(value), vlen, tcl_binary(value, vlen));
}

tcl_value_t *tcl_list_alloc() { return tcl_value("", 0, false); }

int tcl_list_length(tcl_value_t *v) {
  int count = 0;
  tcl_each(tcl_string(v), tcl_length(v) + 1, 0) {
    if (p.token == TWORD) {
      count++;
    }
  }
  return count;
}

#define tcl_list_free(v) tcl_free(v)

tcl_value_t *tcl_list_at(tcl_value_t *v, int index) {
  int i = 0;
  tcl_each(tcl_string(v), tcl_length(v) + 1, 0) {
    if (p.token == TWORD) {
      if (i == index) {
        const char *data = p.from;
        size_t sz = p.to - p.from;
        if (*data == '{') {
          data += 1;
          sz -= 2;
        }
        return tcl_value(data, sz, tcl_binary(data, sz));
      }
      i++;
    }
  }
  return NULL;
}

tcl_value_t *tcl_list_append(tcl_value_t *v, tcl_value_t *tail) {
  if (tcl_length(v) > 0) {
    v = tcl_append(v, tcl_value(" ", 1, false));
  }
  if (tcl_length(tail) > 0) {
    int q = 0;
    const char *p;
    for (p = tcl_string(tail); *p; p++) {
      if (tcl_is_space(*p) || tcl_is_special(*p, 0)) {
        q = 1;
        break;
      }
    }
    if (q) {
      v = tcl_append(v, tcl_value("{", 1, false));
    }
    v = tcl_append(v, tcl_dup(tail));
    if (q) {
      v = tcl_append(v, tcl_value("}", 1, false));
    }
  } else {
    v = tcl_append(v, tcl_value("{}", 2, false));
  }
  return v;
}

/* ----------------------------- */
/* ----------------------------- */
/* ----------------------------- */
/* ----------------------------- */

struct tcl_cmd {
  tcl_value_t *name;
  int arity;
  tcl_cmd_fn_t fn;
  void *user;
  struct tcl_cmd *next;
};

struct tcl_var {
  tcl_value_t *name;
  tcl_value_t *value;
  struct tcl_var *next;
};

struct tcl_env {
  struct tcl_var *vars;
  struct tcl_env *parent;
};

static struct tcl_env *tcl_env_alloc(struct tcl_env *parent) {
  struct tcl_env *env = malloc(sizeof(*env));
  env->vars = NULL;
  env->parent = parent;
  return env;
}

static struct tcl_var *tcl_env_var(struct tcl_env *env, tcl_value_t *name) {
  struct tcl_var *var = malloc(sizeof(struct tcl_var));
  var->name = tcl_dup(name);
  var->next = env->vars;
  var->value = tcl_value("", 0, false);
  env->vars = var;
  return var;
}

static struct tcl_env *tcl_env_free(struct tcl_env *env) {
  struct tcl_env *parent = env->parent;
  while (env->vars) {
    struct tcl_var *var = env->vars;
    env->vars = env->vars->next;
    tcl_free(var->name);
    tcl_free(var->value);
    free(var);
  }
  free(env);
  return parent;
}

tcl_value_t *tcl_var(struct tcl *tcl, tcl_value_t *name, tcl_value_t *value) {
  DBG("var(%s := %.*s)\n", tcl_string(name), tcl_length(value), tcl_string(value));
  struct tcl_var *var;
  for (var = tcl->env->vars; var != NULL; var = var->next) {
    if (strcmp(tcl_string(var->name), tcl_string(name)) == 0) {
      break;
    }
  }
  if (var == NULL) {
    var = tcl_env_var(tcl->env, name);
  }
  if (value != NULL) {
    tcl_free(var->value);
    var->value = tcl_dup(value);
    tcl_free(value);
  }
  return var->value;
}

static void tcl_markposition(struct tcl *tcl, const char *pos) {
  if (!tcl->env->parent && tcl->nestlevel == 1) {
    tcl->errorpos = pos;
  }
}

int tcl_result(struct tcl *tcl, int flow, tcl_value_t *result) {
  DBG("tcl_result %.*s, flow=%d\n", tcl_length(result), tcl_string(result), flow);
  tcl_free(tcl->result);
  tcl->result = result;
  return flow;
}

int tcl_subst(struct tcl *tcl, const char *s, size_t len) {
  DBG("subst(%.*s)\n", (int)len, s);
  if (len == 0) {
    return tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
  }
  switch (s[0]) {
  case '{':
    if (len <= 1) {
      return tcl_result(tcl, FERROR, tcl_value("", 0, false));
    }
    return tcl_result(tcl, FNORMAL, tcl_value(s + 1, len - 2, tcl_binary(s + 1, len - 2)));
  case '$': {
    if (len >= MAX_VAR_LENGTH) {
      return tcl_result(tcl, FERROR, tcl_value("", 0, false));
    }
    tcl_value_t *name = tcl_value(s + 1, len - 1, false);
    int r = tcl_result(tcl, FNORMAL, tcl_dup(tcl_var(tcl, name, NULL)));
    tcl_free(name);
    return r;
  }
  case '[': {
    tcl_value_t *expr = tcl_value(s + 1, len - 2, tcl_binary(s + 1, len - 2));
    int r = tcl_eval(tcl, tcl_string(expr), tcl_length(expr) + 1);
    tcl_free(expr);
    return r;
  }
  default:
    return tcl_result(tcl, FNORMAL, tcl_value(s, len, tcl_binary(s, len)));
  }
}

static int tcl_exec_cmd(struct tcl *tcl, tcl_value_t *list) {
  tcl_value_t *cmdname = tcl_list_at(list, 0);
  struct tcl_cmd *cmd = NULL;
  int r = FERROR;
  for (cmd = tcl->cmds; cmd != NULL; cmd = cmd->next) {
    if (strcmp(tcl_string(cmdname), tcl_string(cmd->name)) == 0) {
      if (cmd->arity == 0 || cmd->arity == tcl_list_length(list)) {
        r = cmd->fn(tcl, list, cmd->user);
        break;
      }
    }
  }
  tcl_free(cmdname);
  return r;
}

int tcl_eval(struct tcl *tcl, const char *s, size_t len) {
  DBG("eval(%.*s)->\n", (int)len, s);
  tcl->nestlevel += 1;
  tcl_value_t *list = tcl_list_alloc();
  tcl_value_t *cur = NULL;
  int result = FNORMAL;
  tcl_each(s, len, 1) {
    DBG("tcl_next %d %.*s\n", p.token, (int)(p.to - p.from), p.from);
    tcl_markposition(tcl, p.from);
    switch (p.token) {
    case TERROR:
      DBG("eval: FERROR, lexer error\n");
      result = tcl_result(tcl, FERROR, tcl_value("", 0, false));
      break;
    case TWORD:
      DBG("token %.*s, length=%d, cur=%p (3.1.1)\n", (int)(p.to - p.from),
          p.from, (int)(p.to - p.from), cur);
      if (cur != NULL) {
        result = tcl_subst(tcl, p.from, p.to - p.from);
        tcl_value_t *part = tcl_dup(tcl->result);
        cur = tcl_append(cur, part);
      } else {
        result = tcl_subst(tcl, p.from, p.to - p.from);
        cur = tcl_dup(tcl->result);
      }
      list = tcl_list_append(list, cur);
      tcl_free(cur);
      cur = NULL;
      break;
    case TPART:
      result = tcl_subst(tcl, p.from, p.to - p.from);
      tcl_value_t *part = tcl_dup(tcl->result);
      cur = tcl_append(cur, part);
      break;
    case TCMD:
      if (tcl_list_length(list) == 0) {
        result = tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
      } else {
        result = tcl_exec_cmd(tcl, list);
      }
      tcl_list_free(list);
      list = tcl_list_alloc();
      break;
    }
    if (result == FERROR) {
      break;
    }
  }
  /* when arrived at the end of the buffer, if the list is non-empty, run that
     last command */
  if (result == FNORMAL && tcl_list_length(list) > 0) {
    result = tcl_exec_cmd(tcl, list);
  }
  tcl_list_free(list);
  tcl->nestlevel -= 1;
  return result;
}

/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
void tcl_register(struct tcl *tcl, const char *name, tcl_cmd_fn_t fn, int arity,
                  void *user) {
  struct tcl_cmd *cmd = malloc(sizeof(struct tcl_cmd));
  cmd->name = tcl_value(name, strlen(name), false);
  cmd->fn = fn;
  cmd->user = user;
  cmd->arity = arity;
  cmd->next = tcl->cmds;
  tcl->cmds = cmd;
}

static int tcl_cmd_set(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *var = tcl_list_at(args, 1);
  tcl_value_t *val = tcl_list_at(args, 2);
  int r = tcl_result(tcl, FNORMAL, tcl_dup(tcl_var(tcl, var, val)));
  tcl_free(var);
  return r;
}

static int tcl_cmd_subst(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *s = tcl_list_at(args, 1);
  int r = tcl_subst(tcl, tcl_string(s), tcl_length(s));
  tcl_free(s);
  return r;
}

#ifndef TCL_DISABLE_PUTS
static int tcl_cmd_puts(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *text = tcl_list_at(args, 1);
  puts(tcl_string(text));
  putchar('\n');
  return tcl_result(tcl, FNORMAL, text);
}
#endif

static int tcl_user_proc(struct tcl *tcl, tcl_value_t *args, void *arg) {
  tcl_value_t *code = (tcl_value_t *)arg;
  tcl_value_t *params = tcl_list_at(code, 2);
  tcl_value_t *body = tcl_list_at(code, 3);
  tcl->env = tcl_env_alloc(tcl->env);
  for (int i = 0; i < tcl_list_length(params); i++) {
    tcl_value_t *param = tcl_list_at(params, i);
    tcl_value_t *v = tcl_list_at(args, i + 1);
    tcl_var(tcl, param, v);
    tcl_free(param);
  }
  tcl_eval(tcl, tcl_string(body), tcl_length(body) + 1);
  tcl->env = tcl_env_free(tcl->env);
  tcl_free(params);
  tcl_free(body);
  return FNORMAL;
}

static int tcl_cmd_proc(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *name = tcl_list_at(args, 1);
  tcl_register(tcl, tcl_string(name), tcl_user_proc, 0, tcl_dup(args));
  tcl_free(name);
  return tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
}

static int tcl_cmd_if(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int i = 1;
  int n = tcl_list_length(args);
  int r = FNORMAL;
  while (i < n) {
    tcl_value_t *cond = tcl_list_at(args, i);
    tcl_value_t *branch = NULL;
    if (i + 1 < n) {
      branch = tcl_list_at(args, i + 1);
    }
    r = tcl_eval(tcl, tcl_string(cond), tcl_length(cond) + 1);
    tcl_free(cond);
    if (r != FNORMAL) {
      tcl_free(branch);
      break;
    }
    if (tcl_int(tcl->result)) {
      r = tcl_eval(tcl, tcl_string(branch), tcl_length(branch) + 1);
      tcl_free(branch);
      break;
    }
    i = i + 2;
    tcl_free(branch);
  }
  return r;
}

static int tcl_cmd_flow(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  int r = FERROR;
  tcl_value_t *flowval = tcl_list_at(args, 0);
  const char *flow = tcl_string(flowval);
  if (strcmp(flow, "break") == 0) {
    r = FBREAK;
  } else if (strcmp(flow, "continue") == 0) {
    r = FAGAIN;
  } else if (strcmp(flow, "return") == 0) {
    r = tcl_result(tcl, FRETURN, tcl_list_at(args, 1));
  }
  tcl_free(flowval);
  return r;
}

static int tcl_cmd_while(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  tcl_value_t *cond = tcl_list_at(args, 1);
  tcl_value_t *loop = tcl_list_at(args, 2);
  for (;;) {
    int r = tcl_eval(tcl, tcl_string(cond), tcl_length(cond) + 1);
    if (r != FNORMAL) {
      tcl_free(cond);
      tcl_free(loop);
      return r;
    }
    if (!tcl_int(tcl->result)) {
      tcl_free(cond);
      tcl_free(loop);
      return FNORMAL;
    }
    r = tcl_eval(tcl, tcl_string(loop), tcl_length(loop) + 1);
    switch (r) {
    case FBREAK:
      tcl_free(cond);
      tcl_free(loop);
      return FNORMAL;
    case FRETURN:
      tcl_free(cond);
      tcl_free(loop);
      return FRETURN;
    case FAGAIN:
      continue;
    case FERROR:
      tcl_free(cond);
      tcl_free(loop);
      return FERROR;
    }
  }
}

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

#ifndef TCL_DISABLE_MATH
enum {
  TOK_END_EXPR = 0,
  TOK_NUMBER = 256,
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
};

static long expr_logic_or(struct expr *expr);
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
  static const char special[] = "|&~<>=!-+*/%()";

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
  } else {
    expr_error(expr, eINVALID_CHAR);
    expr->token = TOK_END_EXPR;
  }
  return expr->token;
}

static long expr_primary(struct expr *expr) {
  long v = 0;
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
    v = expr_logic_or(expr);
    if (lex(expr) != ')')
      expr_error(expr, ePARENTHESES);
    break;
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

static int tcl_expression(const char *expression, long *result)
{
  int op;

  struct expr expr;
  memset(&expr, 0, sizeof(expr));
  expr.pos = expression;
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

static int tcl_cmd_expr(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;

  /* re-construct the expression (it may have been tokenized by the Tcl Lexer) */
  int count = tcl_list_length(args);
  size_t total = 256;
  char *expression = malloc(total);
  if (!expression) {
    return tcl_result(tcl, FERROR, tcl_value("", 0, false));
  }
  *expression = '\0';
  for (int idx = 1; idx < count; idx++) {
    tcl_value_t *tok = tcl_list_at(args, idx);
    if (strlen(expression) + tcl_length(tok) + 1 >= total) {  /* may need to grow the buffer */
      size_t newsize = 2 * total;
      char *newbuf = malloc(newsize);
      if (newbuf) {
        strcpy(newbuf, expression);
        free(expression);
        expression = newbuf;
        total = newsize;
      }
    }
    if (strlen(expression) + tcl_length(tok) < total) {
      if (strlen(expression) > 0)
        strcat(expression, " ");
      strcat(expression, tcl_string(tok));
    }
    tcl_free(tok);
  }
  /* parse expression */
  long result;
  int err = tcl_expression(expression, &result);
  free(expression);

  /* convert result to string */
  char buf[64] = "";
  char *p = buf + sizeof(buf) - 1;
  *p-- = '\0';
  bool neg = (result < 0);
  if (neg) {
    result = -result;
  }
  do {
    *p-- = '0' + (result % 10);
    result = result / 10;
  } while (result > 0);
  if (neg) {
    *p-- = '-';
  }
  p++;

  return tcl_result(tcl, (err == eNONE) ? FNORMAL : FERROR, tcl_value(p, strlen(p), false));
}
#endif  /* TCL_DISABLE_MATH */

/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */
/* ------------------------------------------------------- */

void tcl_init(struct tcl *tcl) {
  memset(tcl, 0, sizeof(struct tcl));
  tcl->env = tcl_env_alloc(NULL);
  tcl->result = tcl_value("", 0, false);
  tcl_register(tcl, "set", tcl_cmd_set, 0, NULL);
  tcl_register(tcl, "subst", tcl_cmd_subst, 2, NULL);
#ifndef TCL_DISABLE_PUTS
  tcl_register(tcl, "puts", tcl_cmd_puts, 2, NULL);
#endif
  tcl_register(tcl, "proc", tcl_cmd_proc, 4, NULL);
  tcl_register(tcl, "if", tcl_cmd_if, 0, NULL);
  tcl_register(tcl, "while", tcl_cmd_while, 3, NULL);
  tcl_register(tcl, "return", tcl_cmd_flow, 0, NULL);
  tcl_register(tcl, "break", tcl_cmd_flow, 1, NULL);
  tcl_register(tcl, "continue", tcl_cmd_flow, 1, NULL);
#ifndef TCL_DISABLE_MATH
  tcl_register(tcl, "expr", tcl_cmd_expr, 0, NULL);
#endif
}

void tcl_destroy(struct tcl *tcl) {
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

const char *tcl_cobs_encode(const char *bindata, size_t *length) {
  assert(bindata);
  assert(length);
  size_t binsz = *length;
  size_t ascsz = binsz + (binsz + 253) / 254 + 1;  /* overhead = 1 byte for each 254, plus zero terminator */
  char *asciiz = malloc(binsz);
  if (asciiz) {
    /* adapted from Wikipedia */
    char *encode = asciiz;  /* pointer to where non-zero bytes from data are copied */
    char *codep = encode++; /* pointer where length code is stored */
    char code = 1;          /* length count */
    for (const char *byte = bindata; binsz--; ++byte) {
      if (*byte) /* byte not zero, write it */
        *encode++ = *byte, ++code;
      if (!*byte || code == 0xff) { /* input is zero or block full, restart */
        *codep = code;
        codep = encode;
        code = 1;
        if (!*byte || binsz)
          ++encode;
      }
    }
    *codep = code;  /* write final code value */
    *encode = '\0'; /* add terminator */
    assert((encode + 1) - asciiz == ascsz);
    *length = ascsz;
  }
  return asciiz;
}

const char *tcl_cobs_decode(const char *asciiz, size_t *length) {
  assert(asciiz);
  assert(length);
  size_t ascsz = *length;
  /* check for trainling zero terminator, we strip it off */
  if (ascsz > 0 && asciiz[ascsz - 1] == '\0')
    ascsz--;
  size_t binsz = (254 * ascsz) / 255;
  char *bindata = malloc(binsz);
  if (bindata) {
    /* adapted from Wikipedia */
    const char *byte = asciiz;  /* pointer to input buffer */
    char *decode = bindata;     /* pointer to output buffer */
    for (char code = 0xff, block = 0; byte < asciiz + ascsz; --block) {
      if (block) {              /* decode block byte */
        assert(decode < bindata + binsz);
        *decode++ = *byte++;
      } else {
        if (code != 0xff)       /* encoded zero, write it */
          *decode++ = 0;
        block = code = *byte++; /* next block length */
        assert(code);           /* may not drop on the zero terminator */
      }
    }
    *length = binsz;
  }
  return bindata;
}

