#ifndef _TCL_H
#define _TCL_H

#include <stdbool.h>

typedef long long tcl_int;

struct tcl_value;
struct tcl;
struct tcl_value;
struct tcl {
  struct tcl_env *env;
  struct tcl_cmd *cmds;
  struct tcl_value *result;
  struct tcl_value *errinfo;
};



/* =========================================================================
    High level interface
   ========================================================================= */

/** tcl_init() initializes the interpreter context.
 *
 *  \param tcl      The interpreter context.
 */
void tcl_init(struct tcl *tcl);

/** tcl_destroy() cleans up the interpreter context, frees all memory.
 *
 *  \param tcl      The interpreter context.
 */
void tcl_destroy(struct tcl *tcl);

/** tcl_eval() runs a script stored in a memory buffer.
 *
 *  \param tcl      The interpreter context.
 *  \param string   The buffer with the script (or part of a script).
 *  \param length   The length of the buffer.
 *
 *  \return 0 on success, 1 on error; other codes are used internally.
 *
 *  \note On completion (of a successful run), the output of the script is
 *        stored in the "result" field of the "tcl" context. You can read this
 *        value with tcl_return().
 */
int tcl_eval(struct tcl *tcl, const char *string, size_t length);

/** tcl_return() returns the result of the script execution (the "return" value
 *  of the script). This data is only valid if tcl_eval() returned success.
 *
 *  \param tcl      The interpreter context.
 *
 *  \note The return value is a pointer to the value in the context; it is not a
 *        copy (and should not be freed). To clean-up the entire context, use
 *        tcl_destroy().
 */
struct tcl_value *tcl_return(struct tcl *tcl);

/** tcl_errorinfo() returns the error code/message and the (approximate) line
 *  number of the error. The error information is cleared after this call.
 *
 *  \param tcl      The interpreter context.
 *  \param code     [out] The numeric error code. This parameter may be set to
 *                  NULL.
 *  \param info     [out] May contain extra information on the error (such as
 *                  the name of a proc or variable). This parameter may be set
 *                  to NULL.
 *  \param line     [out] The (approximate) line number (1-based). This
 *                  parameter may be set to NULL.
 *
 *  \return A pointer to a message describing the error code.
 */
const char *tcl_errorinfo(struct tcl *tcl, int *code, const char **info, int *line);


/* =========================================================================
    Values & lists
   ========================================================================= */

/** tcl_isnumber() returns whether the value of the parameter is a valid integer
 *  number. Note that integers can also be accessed as strings in Tcl.
 *
 *  \param v        The value.
 *
 *  \return The detected value.
 */
bool tcl_isnumber(const struct tcl_value *value);

/** tcl_data() returns a pointer to the start of the contents of a value.
 *
 *  \param value    The value.
 *
 *  \return A pointer to the buffer.
 */
const char *tcl_data(const struct tcl_value *value);

/** tcl_length() returns the length of the contents of the value in characters.
 *
 *  \param value    The value.
 *
 *  \return The number of characters in the buffer of the value.
 *
 *  \note This function does _not_ check for escaped characters.
 */
size_t tcl_length(const struct tcl_value *value);

/** tcl_number() returns the value of a variable after parsing it as an integer
 *  value. The function supports decimal, octal and dexadecimal notation.
 *
 *  \param value    The value.
 *
 *  \return The numeric value of the parameter, or 0 on error.
 */
tcl_int tcl_number(const struct tcl_value *value);

/** tcl_value() creates a value from a C string or data block.
 *
 *  \param data     The contents to store in the value. A copy is made of this
 *                  buffer.
 *  \param len      The length of the data.
 *
 *  \return A pointer to the created value.
 *
 *  \note The value should be deleted with tcl_free().
 */
struct tcl_value *tcl_value(const char *data, size_t len);

/** tcl_free() deallocates a value or a list.
 *
 *  \param v          The value.
 *
 *  \return This function always returns NULL.
 *
 *  \note Lists are implemented as values (strings), so this function
 *        deallocates both.
 */
struct tcl_value *tcl_free(struct tcl_value *v);

/** tcl_list_new() creates an empty list. Use this function to start a new list
 *  (then append items to it). The list must be freed with tcl_free().
 */
struct tcl_value *tcl_list_new(void);

/** tcl_list_length() returns the number of elements in a list.
 *
 *  \param list       The list.
 *
 *  \return The number of elements in the list.
 */
int tcl_list_length(const struct tcl_value *list);

/** tcl_list_item() retrieves an element from the list.
 *
 *  \param list       The list.
 *  \param index      The zero-based index of the element to retrieve.
 *
 *  \return The selected element, or NULL if parameter "index" is out of range.
 *
 *  \note The returned element is a copy, which must be freed with tcl_free().
 */
struct tcl_value *tcl_list_item(struct tcl_value *list, int index);

/** tcl_list_append() appends an item to the list, and frees the item.
 *
 *  \param list       The original list.
 *  \param tail       The item to append.
 *
 *  \return true on success, false on failure.
 *
 *  \note Both the original data in the `list` parameter and the `tail` item
 *        that was appended, are deallocated (freed).
 */
bool tcl_list_append(struct tcl_value *list, struct tcl_value *tail);


/* =========================================================================
    Variables
   ========================================================================= */

/** tcl_var() sets or reads a variable.
 *
 *  \param tcl      The interpreter context.
 *  \param name     The name of the variable.
 *  \param value    The value to set the variable to, or NULL to read the value
 *                  of the variable. See notes below.
 *
 *  \return A pointer to the value in the variable. It may return NULL on
 *          failure, see also the notes below.
 *
 *  \note When reading a variable that does not exist, the function sets an
 *        error and returns NULL.
 *
 *  \note The returned pointer points to the value in the tcl_var structure; it
 *        is not a copy (and must not be freed or changed).
 *
 *  \note The "value" parameter (if not NULL) is owned by the variable after
 *        this function completes. Thus, the parameter should not be freed.
 */
struct tcl_value *tcl_var(struct tcl *tcl, const char *name, struct tcl_value *value);


/* =========================================================================
    User commands
   ========================================================================= */

typedef int (*tcl_cmd_fn_t)(struct tcl *tcl, struct tcl_value *args, void *user);

/** tcl_register() registers a C function to the ParTcl command set.
 *
 *  \param tcl      The interpreter context.
 *  \param name     The name of the command.
 *  \param fn       The function pointer.
 *  \param minargs  The minimum number of parameters of the command, which
 *                  includes the command name itself (so the lowest valie value
 *                  is 1).
 *  \param maxargs  The maximum number of parameters of the command, which
 *                  includes the command name itself. Set this to zero for a
 *                  variable argument list.
 *  \param user     A user value (which is passed to the C function); normally
 *                  set to NULL.
 *
 *  \return A pointer to the command structure that was just added.
 */
struct tcl_cmd *tcl_register(struct tcl *tcl, const char *name, tcl_cmd_fn_t fn, unsigned short minargs, unsigned short maxargs, void *user);

/** tcl_result() sets the result of a C function into the ParTcl environment.
 *
 *  \param tcl      The interpreter context.
 *  \param flow     Should be set to 0 if an error occurred, or 1 on success
 *                  (other values for "flow" are used internally).
 *  \param result   The result (or "return value") of the C function. See notes
 *                  below.
 *
 *  \return This function returns the "flow" parameter. For the C interface, the
 *          return value can be ignored.
 *
 *  \note The "result" parameter is is owned by the interpreter context when
 *        this function completes. Thus, the parameter should not be freed.
 */
int tcl_result(struct tcl *tcl, int flow, struct tcl_value *result);


/* =========================================================================
    Internals
   ========================================================================= */

/** tcl_cur_scope() returns the current scope level. It is zero at the global
 *  level, and is incremented each time that a new local environment for a user
 *  procedure is allocated.
 *
 *  \param tcl      The interpreter context.
 *
 *  \return The active scope.
 */
int tcl_cur_scope(struct tcl *tcl);

/** tcl_append() creates a new value that is the concatenation of the two
 *  parameters, and deletes the input parameters.
 *
 *  \param value    The value to modify.
 *  \param tail     The data to append to parameter `value`.
 *
 *  \return true on success, false on failure (i.e. memory allocation failure).
 *
 *  \note The `value` parameter is modified, meaning that its `data` block is
 *        re-allocated. Any pointer held to the data, is therefore invalid after
 *        the call to tcl_append().
 *  \note The `tail` parameter is deleted by this function.
 */
bool tcl_append(struct tcl_value *value, struct tcl_value *tail);

#endif /* _TCL_H */
