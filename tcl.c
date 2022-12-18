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

static int tcl_is_special(char c, int q) {
  return (c == '$' || (!q && (c == '{' || c == '}' || c == ';' || c == '\r' ||
                              c == '\n')) ||
          c == '[' || c == ']' || c == '"' || c == '\0');
}

static int tcl_is_space(char c) { return (c == ' ' || c == '\t'); }

static int tcl_is_end(char c) {
  return (c == '\n' || c == '\r' || c == ';' || c == '\0');
}

int tcl_next(const char *script, size_t length, const char **from, const char **to, bool *quote) {
  unsigned int i = 0;
  int depth = 0;

  DBG("tcl_next(%.*s)+%d+%d|%d\n", length, script, *from - script, *to - script, *quote);

  /* Skip leading spaces if not quoted */
  for (; !*quote && length > 0 && tcl_is_space(*script); script++, length--)
    {}
  *from = script;
  /* Terminate command if not quoted */
  if (!*quote && length > 0 && tcl_is_end(*script)) {
    *to = script + 1;
    return TCMD;
  }
  if (*script == '$') { /* Variable token, must not start with a space or quote */
    if (tcl_is_space(script[1]) || script[1] == '"') {
      return TERROR;
    }
    int mode = *quote;
    *quote = 0;
    int r = tcl_next(script + 1, length - 1, to, to, quote);
    *quote = mode;
    return ((r == TWORD && *quote) ? TPART : r);
  }

  if (*script == '[' || (!*quote && *script == '{')) {
    /* Interleaving pairs are not welcome, but it simplifies the code */
    char open = *script;
    char close = (open == '[' ? ']' : '}');
    for (i = 1, depth = 1; i < length && depth != 0; i++) {
      if (script[i] == '\\' && i+1 < length && (script[i+1] == open || script[i+1] == close)) {
        i++;  /* escaped brace/bracket, skip both '\' and the character that follows it */
      } else if (script[i] == open) {
        depth++;
      } else if (script[i] == close) {
        depth--;
      } else if (script[i] == BIN_TOKEN && i+3 < length) {
        /* skip the binary block */
        unsigned n = BIN_SIZE(script + i);
        if (i + n + 2 < length) {
          i += n + 2;
        }
      }
    }
  } else if (*script == '"') {
    *quote = !*quote;
    *from = *to = script + 1;
    if (*quote) {
      return TPART;
    }
    if (length < 2 || (!tcl_is_space(script[1]) && !tcl_is_end(script[1]))) {
      return TERROR;
    }
    *from = *to = script + 1;
    return TWORD;
  } else if (*script == ']' || *script == '}') {
    return TERROR;    /* Unbalanced bracket or brace */
  } else if (*script == BIN_TOKEN) {
    i = BIN_SIZE(script) + 3;
    if (i >= length) {
      return TERROR;
    }
  } else {
    while (i < length && (*quote || !tcl_is_space(script[i])) && !tcl_is_special(script[i], *quote)) {
      i++;
    }
  }
  *to = script + i;
  if (i > length || (i == length && depth)) {
    return TERROR;
  }
  if (*quote) {
    return TPART;
  }
  return (tcl_is_space(script[i]) || tcl_is_end(script[i])) ? TWORD : TPART;
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
                             &p.quote)) != TERROR) ||                          \
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

tcl_value_t *tcl_var(struct tcl *tcl, tcl_value_t *name, tcl_value_t *v) {
  DBG("var(%s := %.*s)\n", tcl_string(name), tcl_length(v), tcl_string(v));
  struct tcl_var *var;
  for (var = tcl->env->vars; var != NULL; var = var->next) {
    if (strcmp(tcl_string(var->name), tcl_string(name)) == 0) {
      break;
    }
  }
  if (var == NULL) {
    var = tcl_env_var(tcl->env, name);
  }
  if (v != NULL) {
    tcl_free(var->value);
    var->value = tcl_dup(v);
    tcl_free(v);
  }
  return var->value;
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
    char buf[5 + MAX_VAR_LENGTH] = "set ";
    strncat(buf, s + 1, len - 1);
    return tcl_eval(tcl, buf, strlen(buf) + 1);
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
  tcl_value_t *list = tcl_list_alloc();
  tcl_value_t *cur = NULL;
  tcl_each(s, len, 1) {
    DBG("tcl_next %d %.*s\n", p.token, (int)(p.to - p.from), p.from);
    switch (p.token) {
    case TERROR:
      DBG("eval: FERROR, lexer error\n");
      return tcl_result(tcl, FERROR, tcl_value("", 0, false));
    case TWORD:
      DBG("token %.*s, length=%d, cur=%p (3.1.1)\n", (int)(p.to - p.from),
          p.from, (int)(p.to - p.from), cur);
      if (cur != NULL) {
        tcl_subst(tcl, p.from, p.to - p.from);
        tcl_value_t *part = tcl_dup(tcl->result);
        cur = tcl_append(cur, part);
      } else {
        tcl_subst(tcl, p.from, p.to - p.from);
        cur = tcl_dup(tcl->result);
      }
      list = tcl_list_append(list, cur);
      tcl_free(cur);
      cur = NULL;
      break;
    case TPART:
      tcl_subst(tcl, p.from, p.to - p.from);
      tcl_value_t *part = tcl_dup(tcl->result);
      cur = tcl_append(cur, part);
      break;
    case TCMD:
      if (tcl_list_length(list) == 0) {
        tcl_result(tcl, FNORMAL, tcl_value("", 0, false));
      } else {
        int r = tcl_exec_cmd(tcl, list);
        if (r != FNORMAL) {
          tcl_list_free(list);
          return r;
        }
      }
      tcl_list_free(list);
      list = tcl_list_alloc();
      break;
    }
  }
  /* when arrived at the end of the buffer, if the list is non-empty, run that
     last command */
  int r = FNORMAL;
  if (tcl_list_length(list) > 0) {
    r = tcl_exec_cmd(tcl, list);
  }
  tcl_list_free(list);
  return r;
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

#ifndef TCL_DISABLE_MATH
static int tcl_cmd_math(struct tcl *tcl, tcl_value_t *args, void *arg) {
  (void)arg;
  char buf[64];
  tcl_value_t *opval = tcl_list_at(args, 0);
  tcl_value_t *aval = tcl_list_at(args, 1);
  tcl_value_t *bval = tcl_list_at(args, 2);
  const char *op = tcl_string(opval);
  int a = tcl_int(aval);
  int b = tcl_int(bval);
  int c = 0;
  if (op[0] == '+') {
    c = a + b;
  } else if (op[0] == '-') {
    c = a - b;
  } else if (op[0] == '*') {
    c = a * b;
  } else if (op[0] == '/') {
    c = a / b;
  } else if (op[0] == '>' && op[1] == '\0') {
    c = a > b;
  } else if (op[0] == '>' && op[1] == '=') {
    c = a >= b;
  } else if (op[0] == '<' && op[1] == '\0') {
    c = a < b;
  } else if (op[0] == '<' && op[1] == '=') {
    c = a <= b;
  } else if (op[0] == '=' && op[1] == '=') {
    c = a == b;
  } else if (op[0] == '!' && op[1] == '=') {
    c = a != b;
  }

  char *p = buf + sizeof(buf) - 1;
  char neg = (c < 0);
  *p-- = 0;
  if (neg) {
    c = -c;
  }
  do {
    *p-- = '0' + (c % 10);
    c = c / 10;
  } while (c > 0);
  if (neg) {
    *p-- = '-';
  }
  p++;

  tcl_free(opval);
  tcl_free(aval);
  tcl_free(bval);
  return tcl_result(tcl, FNORMAL, tcl_value(p, strlen(p), false));
}
#endif

void tcl_init(struct tcl *tcl) {
  tcl->env = tcl_env_alloc(NULL);
  tcl->result = tcl_value("", 0, false);
  tcl->cmds = NULL;
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
  char *math[] = {"+", "-", "*", "/", ">", ">=", "<", "<=", "==", "!="};
  for (unsigned int i = 0; i < (sizeof(math) / sizeof(math[0])); i++) {
    tcl_register(tcl, math[i], tcl_cmd_math, 3, NULL);
  }
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

#ifdef TEST
#define CHUNK 1024

int main() {
  struct tcl tcl;
  int buflen = CHUNK;
  char *buf = malloc(buflen);
  int i = 0;

  tcl_init(&tcl);
  while (1) {
    int inp = fgetc(stdin);

    if (i > buflen - 1) {
      buf = realloc(buf, buflen += CHUNK);
    }

    if (inp == 0 || inp == EOF) {
      break;
    }

    buf[i++] = inp;

    tcl_each(buf, i, 1) {
      if (p.token == TERROR && (p.to - buf) != i) {
        memset(buf, 0, buflen);
        i = 0;
        break;
      } else if (p.token == TCMD && *(p.from) != '\0') {
        int r = tcl_eval(&tcl, buf, strlen(buf));
        if (r != FERROR) {
          printf("result> %.*s\n", tcl_length(tcl.result),
                 tcl_string(tcl.result));
        } else {
          printf("?!\n");
        }

        memset(buf, 0, buflen);
        i = 0;
        break;
      }
    }
  }

  free(buf);

  if (i) {
    printf("incomplete input\n");
    return -1;
  }

  return 0;
}
#endif
