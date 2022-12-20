#ifndef _TCL_H
#define _TCL_H

#include <stdbool.h>

struct tcl_env;
struct tcl_cmd;
typedef char tcl_value_t;
struct tcl {
  struct tcl_env *env;
  struct tcl_cmd *cmds;
  tcl_value_t *result;
  const char *errorpos;
  short errorcode;
  short nestlevel;
};


/* =========================================================================
    High level interface
   ========================================================================= */

/** tcl_init() initializes the interpreter context.
 *  \param tcl      The interpreter context.
 */
void tcl_init(struct tcl *tcl);

/** tcl_destroy() cleans up the interpreter context, frees all memory.
 *  \param tcl      The interpreter context.
 */
void tcl_destroy(struct tcl *tcl);

/** tcl_eval() runs a script stored in a memory buffer.
 *  \param tcl      The interpreter context.
 *  \param string   The buffer with the script (or part of a script).
 *  \param length   The length of the buffer.
 *
 *  \return 0 on error, 1 on success; other non-zero codes are used internally
 *          (and may be assumed "success").
 *
 *  \note On completion (of a successful run), the output of the script is
 *        stored in the "result" field of the "tcl" context. You can read this
 *        value with `tcl_string`.
 */
int tcl_eval(struct tcl *tcl, const char *string, size_t length);

/** tcl_errorpos() returns the (approximate) line & column number of the
 *  error.
 *  \param tcl      The interpreter context.
 *  \param script   The buffer with the script.
 *  \param line     [out] The line number (1-based).
 *  \param column   [out] The column number (1-based).
 */
void tcl_errorpos(struct tcl *tcl, const char *script, int *line, int *column);
enum {
  TCLERR_GENERAL,     /**< unspecified error */
  TCLERR_SYNTAX,      /**< syntax error, e.g. unbalanced brackets */
  TCLERR_MEMORY,      /**< memory allocation error */
  TCLERR_EXPR,        /**< error in expression */
  TCLERR_CMDUNKNOWN,  /**< unknown command (mismatch in name or arity) */
  TCLERR_VARUNKNOWN,  /**< unknown variable name */
  TCLERR_VARNAME,     /**< invalid variable name (e.g. too long) */
  TCLERR_PARAM,       /**< incorrect (or missing) parameter to a command */
};


/* =========================================================================
    Values & lists
   ========================================================================= */

/** tcl_type() returns the type of a value. Note that integers can also be
 *  accessed as strings in Tcl.
 *  \param v        The value.
 *
 *  \return The detected value.
 */
int tcl_type(tcl_value_t *v);
enum {
  TCLTYPE_EMPTY,
  TCLTYPE_STRING,
  TCLTYPE_INT,
  TCLTYPE_BLOB,
};

/** tcl_string() returns a pointer to the start of the contents of a value. If
 ** the value is binary blob, it returns a pointer to the start of the raw data.
 *  \param v        The value.
 *
 *  \return A pointer to the buffer.
 */
const char *tcl_string(tcl_value_t *v);

/** tcl_length() returns the length of the contents of the value in bytes.
 *  \param v        The value.
 *
 *  \return The number of bytes in the buffer of the value.
 */
size_t tcl_length(tcl_value_t *v);

/** tcl_int() returns the value of a variable after parsing it as an integer
 *  value. The function supports decimal, octal and dexadecimal notation.
 *  \param v        The value.
 *
 *  \return The numeric value of the parameter, or 0 on error.
 */
long tcl_int(tcl_value_t *v);

/** tcl_value() creates a value from a C string or data block.
 *  \param data     The contents to store in the value.
 *  \param len      The length of the data.
 *  \param binary   If true, the contents of "data" is considered a binary blob
 *
 *  \return A pointer to the created value.
 *
 *  \note The value should be deleted with tcl_free().
 *
 *  \note Even if parameter "binary" is false, the data block may be stored as
 *        binary, based on its contents.
 */
tcl_value_t *tcl_value(const char *data, size_t len, bool binary);

/** tcl_free() deallocates a value or a list.
 *  \param v          The value.
 *
 *  \return This function always returns NULL.
 *
 *  \note Lists are implemented as values, but you should use tcl_list_free() to
 *        deallocate lists.
 */
tcl_value_t *tcl_free(tcl_value_t *v);

/** tcl_list_count() returns the number of elements in a list.
 *  \param list       The list.
 *
 *  \return The number of elements in the list.
 */
int tcl_list_count(tcl_value_t *list);

/** tcl_list_at() retrieves an element from the list.
 *  \param list       The list.
 *  \param index      The zero-based index of the element to retrieve.
 *
 *  \return The selected element, or NULL if parameter "index" is out of range.
 *
 *  \note The returned element is a copy, which must be freed with tcl_free().
 */
tcl_value_t *tcl_list_at(tcl_value_t *list, int index);

/** tcl_list_append() appends an item to the list, and frees the item.
 *  \param list       The original list.
 *  \param tail       The item to append.
 *
 *  \return The list with the item appended.
 *
 *  \note Both the original list and the item that was appended, are
 *        deallocated (freed).
 */
tcl_value_t *tcl_list_append(tcl_value_t *list, tcl_value_t *tail);


/* =========================================================================
    Variables
   ========================================================================= */

/** tcl_var() sets or reads a variable
 *  \param tcl      The interpreter context.
 *  \param name     The name of the variable.
 *  \param value    The value to set the variable to, or NULL to read the value
 *                  of the variable.
 *
 *  \return A pointer to the value in the variable.
 *
 *  \note When reading a variable that does not exist, an new variable is
 *        created, with empty contents.
 */
tcl_value_t *tcl_var(struct tcl *tcl, tcl_value_t *name, tcl_value_t *value);


/* =========================================================================
    User commands
   ========================================================================= */

typedef int (*tcl_cmd_fn_t)(struct tcl *tcl, tcl_value_t *args, void *user);

/** tcl_register() registers a C function to the ParTcl command set.
 *  \param tcl      The interpreter context.
 *  \param name     The name of the command.
 *  \param fn       The function pointer.
 *  \param arity    The number of parameters of the command, which includes the
 *                  command name itself. Set this to zero for a variable
 *                  argument list.
 *  \param user     A user value (which is passed to the C function).
 */
void tcl_register(struct tcl *tcl, const char *name, tcl_cmd_fn_t fn, int arity, void *user);

/** tcl_result() sets the result of a C function into the ParTcl environment.
 *  \param tcl      The interpreter context.
 *  \param flow     Should be set to 0 if an error occurred, or 1 on success
 *                  (other values for "flow" are used internally).
 *  \param result   The result (or "return value") of the C function.
 *
 *  \return This function returs the "flow" parameter. For the C interface, the
 *          return value can be ignored.
 */
int tcl_result(struct tcl *tcl, int flow, tcl_value_t *result);


/* =========================================================================
    COBS encoding
   ========================================================================= */

/** tcl_cobs_encode() encodes a binary data block such that no embedded zero
 *  bytes occur in the middle; a zero-terminator is appended to the end, though
 *  (COBS encoding).
 *  \param bindata  The block with binary data.
 *  \param length   [in/out] On input, the length of the bindata buffer; on
 *                  output, the size of the output buffer.
 *
 *  \return A pointer to a buffer with the encoded data (or NULL on failure).
 *
 *  \note The returned memory block must be deallocated with free().
 *
 *  \note The returned length is the same as strlen() of the returned buffer,
 *        plus 1 for the zero-terminator.
 */
const char *tcl_cobs_encode(const char *bindata, size_t *length);

/** tcl_cobs_decode() decodes an COBS-encoded block, and returns the original
 *  binary encoded block.
 *  \param asciiz   The block with encoded data.
 *  \param length   [in/out] On input, the length of the asciiz buffer; on
 *                  output, the size of the output buffer.
 *
 *  \return A pointer to a buffer with the decoded data (or NULL on failure).
 *
 *  \note The returned memory block must be deallocated with free().
 */
const char *tcl_cobs_decode(const char *asciiz, size_t *length);

#endif /* _TCL_H */
