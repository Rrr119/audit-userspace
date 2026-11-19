/*
 * audit-rule-compiler.c - validate and normalize audit rule files
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libaudit.h"

enum rule_kind {
	RULE_SYSCALL,
	RULE_WATCH,
	RULE_REMOVE_WATCH
};

enum item_kind {
	ITEM_RULE,
	ITEM_CONTROL,
	ITEM_COMMENT
};

struct rule_field {
	char *name;
	int id;
	char op[3];
	char *value;
	int line;
};

struct field_compare {
	char *left;
	int left_id;
	char op[3];
	char *right;
	int right_id;
	int line;
};

struct rule {
	enum rule_kind kind;
	char directive;
	char *action;
	char *list;
	struct rule_field *fields;
	size_t field_count;
	size_t field_alloc;
	struct field_compare *compares;
	size_t compare_count;
	size_t compare_alloc;
	char **syscalls;
	size_t syscall_count;
	size_t syscall_alloc;
	char **keys;
	size_t key_count;
	size_t key_alloc;
	char *path;
	char *perm;
	bool explicit_all;
	bool all;
	bool has_perm;
	bool arch_after_syscall;
	bool removed;
	bool has_error;
	const char *file;
	int line;
};

struct item {
	enum item_kind kind;
	struct rule *rule;
	char *text;
	const char *file;
	int line;
};

struct strbuf {
	char *data;
	size_t len;
	size_t alloc;
};

static struct rule **g_rules;
static size_t g_rule_count;
static size_t g_rule_alloc;
static struct item *g_items;
static size_t g_item_count;
static size_t g_item_alloc;

static bool g_check_only;
static bool g_quiet;
static bool g_strict;
static bool g_keep_comments;
static bool g_minimize = true;
static bool g_force;
static const char *g_output;
static int g_errors;
static int g_warnings;
static int g_conflicts;
static int g_duplicates;

/*
 * xmalloc - allocate memory or terminate
 * @size: number of bytes to allocate
 *
 * Returns: Pointer to the new allocation.
 */
static void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL) {
		fputs("audit-rule-compiler: out of memory\n", stderr);
		exit(EXIT_FAILURE);
	}
	return ptr;
}

/*
 * xrealloc - resize an allocation or terminate
 * @ptr: existing allocation
 * @size: requested size
 *
 * Returns: Pointer to the resized allocation.
 */
static void *xrealloc(void *ptr, size_t size)
{
	void *new_ptr = realloc(ptr, size);

	if (new_ptr == NULL) {
		fputs("audit-rule-compiler: out of memory\n", stderr);
		exit(EXIT_FAILURE);
	}
	return new_ptr;
}

/*
 * xstrdup - duplicate a string or terminate
 * @str: string to duplicate
 *
 * Returns: Newly allocated string.
 */
static char *xstrdup(const char *str)
{
	char *copy = strdup(str);

	if (copy == NULL) {
		fputs("audit-rule-compiler: out of memory\n", stderr);
		exit(EXIT_FAILURE);
	}
	return copy;
}

/*
 * xstrndup - duplicate a bounded string or terminate
 * @str: string to duplicate
 * @len: maximum number of bytes
 *
 * Returns: Newly allocated string.
 */
static char *xstrndup(const char *str, size_t len)
{
	char *copy = strndup(str, len);

	if (copy == NULL) {
		fputs("audit-rule-compiler: out of memory\n", stderr);
		exit(EXIT_FAILURE);
	}
	return copy;
}

/*
 * sb_init - initialize a string builder
 * @sb: string builder
 *
 * Returns: None.
 */
static void sb_init(struct strbuf *sb)
{
	sb->data = NULL;
	sb->len = 0;
	sb->alloc = 0;
}

/*
 * sb_reserve - ensure a string builder has room
 * @sb: string builder
 * @extra: additional bytes needed
 *
 * Returns: None.
 */
static void sb_reserve(struct strbuf *sb, size_t extra)
{
	size_t need = sb->len + extra + 1;

	if (need <= sb->alloc)
		return;
	if (sb->alloc == 0)
		sb->alloc = 64;
	while (sb->alloc < need)
		sb->alloc *= 2;
	sb->data = xrealloc(sb->data, sb->alloc);
}

/*
 * sb_putc - append one character
 * @sb: string builder
 * @ch: character to append
 *
 * Returns: None.
 */
static void sb_putc(struct strbuf *sb, char ch)
{
	sb_reserve(sb, 1);
	sb->data[sb->len++] = ch;
	sb->data[sb->len] = '\0';
}

/*
 * sb_puts - append a string
 * @sb: string builder
 * @str: string to append
 *
 * Returns: None.
 */
static void sb_puts(struct strbuf *sb, const char *str)
{
	size_t len = strlen(str);

	sb_reserve(sb, len);
	memcpy(sb->data + sb->len, str, len);
	sb->len += len;
	sb->data[sb->len] = '\0';
}

/*
 * sb_printf - append formatted text
 * @sb: string builder
 * @fmt: printf format
 *
 * Returns: None.
 */
static void sb_printf(struct strbuf *sb, const char *fmt, ...)
{
	va_list ap;
	va_list copy;
	int len;

	va_start(ap, fmt);
	va_copy(copy, ap);
	len = vsnprintf(NULL, 0, fmt, copy);
	va_end(copy);
	if (len < 0) {
		va_end(ap);
		return;
	}
	sb_reserve(sb, (size_t)len);
	vsnprintf(sb->data + sb->len, sb->alloc - sb->len, fmt, ap);
	sb->len += (size_t)len;
	va_end(ap);
}

/*
 * sb_escape - append a token, escaping spaces and backslashes
 * @sb: string builder
 * @str: token to append
 *
 * Returns: None.
 */
static void sb_escape(struct strbuf *sb, const char *str)
{
	const char *ptr;

	for (ptr = str; *ptr; ptr++) {
		if (*ptr == ' ' || *ptr == '\\')
			sb_putc(sb, '\\');
		sb_putc(sb, *ptr);
	}
}

/*
 * sb_free - release a string builder
 * @sb: string builder
 *
 * Returns: None.
 */
static void sb_free(struct strbuf *sb)
{
	free(sb->data);
	sb->data = NULL;
	sb->len = 0;
	sb->alloc = 0;
}

/*
 * vdiag - print one source-aware diagnostic
 * @file: source file name
 * @line: source line number
 * @level: diagnostic level
 * @fmt: printf format
 * @ap: format arguments
 *
 * Returns: None.
 */
static void vdiag(const char *file, int line, const char *level,
		  const char *fmt, va_list ap)
{
	fprintf(stderr, "%s:%d: %s: ", file ? file : "<input>", line, level);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

/*
 * diag_error - report an error at a source location
 * @file: source file name
 * @line: source line number
 * @fmt: printf format
 *
 * Returns: None.
 */
static void diag_error(const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	g_errors++;
	va_start(ap, fmt);
	vdiag(file, line, "error", fmt, ap);
	va_end(ap);
}

/*
 * rule_conflict - report a field conflict on a rule
 * @rule: affected rule
 * @fmt: printf format
 *
 * Returns: None.
 */
static void rule_conflict(struct rule *rule, const char *fmt, ...)
{
	va_list ap;

	g_errors++;
	g_conflicts++;
	rule->has_error = true;
	va_start(ap, fmt);
	vdiag(rule->file, rule->line, "error: conflict", fmt, ap);
	va_end(ap);
}

/*
 * rule_error - report a syntax or context error on a rule
 * @rule: affected rule
 * @fmt: printf format
 *
 * Returns: None.
 */
static void rule_error(struct rule *rule, const char *fmt, ...)
{
	va_list ap;

	g_errors++;
	rule->has_error = true;
	va_start(ap, fmt);
	vdiag(rule->file, rule->line, "error", fmt, ap);
	va_end(ap);
}

/*
 * rule_warning - report a warning on a rule
 * @rule: affected rule
 * @fmt: printf format
 *
 * Returns: None.
 */
static void rule_warning(const struct rule *rule, const char *fmt, ...)
{
	va_list ap;

	g_warnings++;
	if (g_quiet)
		return;
	va_start(ap, fmt);
	vdiag(rule->file, rule->line, "warning", fmt, ap);
	va_end(ap);
}

/*
 * add_rule_ptr - remember a parsed rule
 * @rule: rule to remember
 *
 * Returns: None.
 */
static void add_rule_ptr(struct rule *rule)
{
	if (g_rule_count == g_rule_alloc) {
		g_rule_alloc = g_rule_alloc ? g_rule_alloc * 2 : 64;
		g_rules = xrealloc(g_rules,
				   g_rule_alloc * sizeof(*g_rules));
	}
	g_rules[g_rule_count++] = rule;
}

/*
 * add_item - remember one output item
 * @kind: item kind
 * @rule: rule for ITEM_RULE
 * @text: text for controls and comments
 * @file: source file
 * @line: source line
 *
 * Returns: None.
 */
static void add_item(enum item_kind kind, struct rule *rule, char *text,
		     const char *file, int line)
{
	struct item *item;

	if (g_item_count == g_item_alloc) {
		g_item_alloc = g_item_alloc ? g_item_alloc * 2 : 64;
		g_items = xrealloc(g_items,
				   g_item_alloc * sizeof(*g_items));
	}
	item = &g_items[g_item_count++];
	item->kind = kind;
	item->rule = rule;
	item->text = text;
	item->file = file;
	item->line = line;
}

/*
 * new_rule - allocate and initialize a rule
 * @kind: rule kind
 * @directive: source directive
 * @file: source file
 * @line: source line
 *
 * Returns: Newly allocated rule.
 */
static struct rule *new_rule(enum rule_kind kind, char directive,
			     const char *file, int line)
{
	struct rule *rule = xmalloc(sizeof(*rule));

	memset(rule, 0, sizeof(*rule));
	rule->kind = kind;
	rule->directive = directive;
	rule->file = file;
	rule->line = line;
	return rule;
}

/*
 * free_rule - release a rule and its strings
 * @rule: rule to release
 *
 * Returns: None.
 */
static void free_rule(struct rule *rule)
{
	size_t i;

	if (rule == NULL)
		return;
	for (i = 0; i < rule->field_count; i++) {
		free(rule->fields[i].name);
		free(rule->fields[i].value);
	}
	for (i = 0; i < rule->compare_count; i++) {
		free(rule->compares[i].left);
		free(rule->compares[i].right);
	}
	for (i = 0; i < rule->syscall_count; i++)
		free(rule->syscalls[i]);
	for (i = 0; i < rule->key_count; i++)
		free(rule->keys[i]);
	free(rule->fields);
	free(rule->compares);
	free(rule->syscalls);
	free(rule->keys);
	free(rule->action);
	free(rule->list);
	free(rule->path);
	free(rule->perm);
	free(rule);
}

/*
 * grow_rule_array - reserve space in a rule array
 * @array: array pointer
 * @count: current element count
 * @alloc: current allocation count
 * @size: element size
 *
 * Returns: None.
 */
static void grow_rule_array(void **array, size_t count, size_t *alloc,
			    size_t size)
{
	if (count < *alloc)
		return;
	*alloc = *alloc ? *alloc * 2 : 8;
	*array = xrealloc(*array, *alloc * size);
}

/*
 * rule_add_field - append a field to a rule
 * @rule: destination rule
 * @name: canonical field name
 * @id: audit field id
 * @op: comparison operator
 * @value: field value
 *
 * Returns: None.
 */
static void rule_add_field(struct rule *rule, const char *name, int id,
			   const char *op, const char *value)
{
	struct rule_field *field;

	grow_rule_array((void **)&rule->fields, rule->field_count,
			&rule->field_alloc, sizeof(*rule->fields));
	field = &rule->fields[rule->field_count++];
	field->name = xstrdup(name);
	field->id = id;
	snprintf(field->op, sizeof(field->op), "%s", op);
	field->value = xstrdup(value);
	field->line = rule->line;
	if (id == AUDIT_PERM)
		rule->has_perm = true;
}

/*
 * rule_add_compare - append an interfield comparison
 * @rule: destination rule
 * @left: left field name
 * @left_id: left field id
 * @op: comparison operator
 * @right: right field name
 * @right_id: right field id
 *
 * Returns: None.
 */
static void rule_add_compare(struct rule *rule, const char *left, int left_id,
			     const char *op, const char *right, int right_id)
{
	struct field_compare *comp;

	grow_rule_array((void **)&rule->compares, rule->compare_count,
			&rule->compare_alloc, sizeof(*rule->compares));
	comp = &rule->compares[rule->compare_count++];
	comp->left = xstrdup(left);
	comp->left_id = left_id;
	snprintf(comp->op, sizeof(comp->op), "%s", op);
	comp->right = xstrdup(right);
	comp->right_id = right_id;
	comp->line = rule->line;
}

/*
 * rule_add_syscall - append a syscall name
 * @rule: destination rule
 * @name: syscall or io_uring operation name
 *
 * Returns: None.
 */
static void rule_add_syscall(struct rule *rule, const char *name)
{
	size_t i;

	if (strcmp(name, "all") == 0) {
		rule->explicit_all = true;
		return;
	}
	for (i = 0; i < rule->syscall_count; i++) {
		if (strcmp(rule->syscalls[i], name) == 0) {
			rule_warning(rule, "duplicate syscall '%s'", name);
			return;
		}
	}
	grow_rule_array((void **)&rule->syscalls, rule->syscall_count,
			&rule->syscall_alloc, sizeof(*rule->syscalls));
	rule->syscalls[rule->syscall_count++] = xstrdup(name);
}

/*
 * rule_add_key - append a filter key
 * @rule: destination rule
 * @key: key value
 *
 * Returns: None.
 */
static void rule_add_key(struct rule *rule, const char *key)
{
	size_t i;

	if (key[0] == '\0') {
		rule_error(rule, "key must not be empty");
		return;
	}
	if (strlen(key) > AUDIT_MAX_KEY_LEN) {
		rule_error(rule, "key exceeds %d bytes", AUDIT_MAX_KEY_LEN);
		return;
	}
	for (i = 0; i < rule->key_count; i++) {
		if (strcmp(rule->keys[i], key) == 0) {
			rule_warning(rule, "duplicate key '%s'", key);
			return;
		}
	}
	grow_rule_array((void **)&rule->keys, rule->key_count,
			&rule->key_alloc, sizeof(*rule->keys));
	rule->keys[rule->key_count++] = xstrdup(key);
}

/*
 * is_action - check whether a string is a valid rule action
 * @str: string to check
 *
 * Returns: True when the action is known.
 */
static bool is_action(const char *str)
{
	return strcmp(str, "always") == 0 || strcmp(str, "never") == 0 ||
	       strcmp(str, "possible") == 0;
}

/*
 * normalize_list - map deprecated list names to current names
 * @str: list name
 *
 * Returns: Canonical list name or NULL when unknown.
 */
static const char *normalize_list(const char *str)
{
	if (strcmp(str, "exit") == 0)
		return "exit";
	if (strcmp(str, "task") == 0)
		return "task";
	if (strcmp(str, "user") == 0)
		return "user";
	if (strcmp(str, "exclude") == 0)
		return "exclude";
	if (strcmp(str, "filesystem") == 0)
		return "filesystem";
	if (strcmp(str, "io_uring") == 0)
		return "io_uring";
	if (strcmp(str, "entry") == 0)
		return "exit";
	return NULL;
}

/*
 * parse_action_list - parse an -a/-A/-d action,list argument
 * @rule: destination rule
 * @arg: action,list text
 *
 * Returns: Zero on success, negative errno value on failure.
 */
static int parse_action_list(struct rule *rule, const char *arg)
{
	char *copy = xstrdup(arg);
	char *comma = strchr(copy, ',');
	const char *first;
	const char *second;
	const char *list;

	if (comma == NULL || strchr(comma + 1, ',') != NULL) {
		rule_error(rule, "expected action,list in '%s'", arg);
		free(copy);
		return -EINVAL;
	}
	*comma = '\0';
	first = copy;
	second = comma + 1;

	if (is_action(first) && normalize_list(second) != NULL) {
		rule->action = xstrdup(first);
		list = normalize_list(second);
	} else if (normalize_list(first) != NULL && is_action(second)) {
		list = normalize_list(first);
		rule->action = xstrdup(second);
	} else {
		rule_error(rule, "invalid action or list in '%s'", arg);
		free(copy);
		return -EINVAL;
	}
	rule->list = xstrdup(list);
	free(copy);
	if (strcmp(rule->action, "possible") == 0) {
		rule_error(rule, "action 'possible' is deprecated");
		return -EINVAL;
	}
	if (strcmp(list, "entry") == 0)
		rule_warning(rule, "'entry' list is deprecated, using 'exit'");
	return 0;
}

/*
 * split_operator - split field[op]value at the first audit operator
 * @arg: argument text
 * @name: returned field name
 * @op: returned operator
 * @value: returned value
 *
 * Returns: Zero on success, negative errno value on failure.
 */
static int split_operator(const char *arg, char **name, char **op,
			  char **value)
{
	static const char *two_char_ops[] = { "!=", ">=", "<=", "&=" };
	static const char *one_char_ops[] = { "=", ">", "<", "&" };
	const char *split = NULL;
	const char *match = NULL;
	size_t i;

	for (i = 0; i < sizeof(two_char_ops) / sizeof(two_char_ops[0]); i++) {
		split = strstr(arg, two_char_ops[i]);
		if (split != NULL) {
			match = two_char_ops[i];
			break;
		}
	}
	if (split == NULL) {
		for (i = 0; i < sizeof(one_char_ops) / sizeof(one_char_ops[0]);
		     i++) {
			split = strstr(arg, one_char_ops[i]);
			if (split != NULL) {
				match = one_char_ops[i];
				break;
			}
		}
	}
	if (split == NULL || split == arg || split[strlen(match)] == '\0')
		return -EINVAL;
	*name = xstrndup(arg, (size_t)(split - arg));
	*op = xstrdup(match);
	*value = xstrdup(split + strlen(match));
	return 0;
}

/*
 * trim_path - remove trailing slashes from a path
 * @path: path to normalize
 *
 * Returns: Newly allocated normalized path.
 */
static char *trim_path(const char *path)
{
	char *copy = xstrdup(path);
	size_t len = strlen(copy);

	while (len > 1 && copy[len - 1] == '/')
		copy[--len] = '\0';
	return copy;
}

/*
 * perm_bits - parse an rwxa permission mask
 * @str: permission string
 *
 * Returns: Mask value, or -1 when a character is invalid.
 */
static int perm_bits(const char *str)
{
	int bits = 0;

	if (*str == '\0')
		return -1;
	for (; *str; str++) {
		switch (tolower((unsigned char)*str)) {
		case 'r':
			bits |= 1;
			break;
		case 'w':
			bits |= 2;
			break;
		case 'x':
			bits |= 4;
			break;
		case 'a':
			bits |= 8;
			break;
		default:
			return -1;
		}
	}
	return bits;
}

/*
 * perm_string - format a permission mask in canonical order
 * @bits: permission mask
 *
 * Returns: Static canonical permission string.
 */
static const char *perm_string(int bits)
{
	static char buf[5];
	size_t pos = 0;

	if (bits & 1)
		buf[pos++] = 'r';
	if (bits & 2)
		buf[pos++] = 'w';
	if (bits & 4)
		buf[pos++] = 'x';
	if (bits & 8)
		buf[pos++] = 'a';
	buf[pos] = '\0';
	return buf;
}

/*
 * is_string_field - identify fields that take string compare operators
 * @id: audit field id
 *
 * Returns: True for string identity and subject fields.
 */
static bool is_string_field(int id)
{
	switch (id) {
	case AUDIT_OBJ_USER:
	case AUDIT_OBJ_ROLE:
	case AUDIT_OBJ_TYPE:
	case AUDIT_OBJ_LEV_LOW:
	case AUDIT_OBJ_LEV_HIGH:
	case AUDIT_WATCH:
	case AUDIT_DIR:
	case AUDIT_SUBJ_USER:
	case AUDIT_SUBJ_ROLE:
	case AUDIT_SUBJ_TYPE:
	case AUDIT_SUBJ_SEN:
	case AUDIT_SUBJ_CLR:
	case AUDIT_EXE:
		return true;
	default:
		return false;
	}
}

/*
 * field_operator_valid - check operators allowed for one field
 * @id: audit field id
 * @op: operator
 *
 * Returns: True when the operator is valid for the field.
 */
static bool field_operator_valid(int id, const char *op)
{
	if (id == AUDIT_PERM)
		return strcmp(op, "=") == 0;
	if (id == AUDIT_ARCH || id == AUDIT_MSGTYPE || id == AUDIT_FSTYPE ||
	    id == AUDIT_FILETYPE || id == AUDIT_INODE ||
	    id == AUDIT_SUCCESS)
		return strcmp(op, "=") == 0 || strcmp(op, "!=") == 0;
	if (is_string_field(id))
		return strcmp(op, "=") == 0 || strcmp(op, "!=") == 0;
	return true;
}

/*
 * parse_field - parse and append one -F field
 * @rule: destination rule
 * @arg: field[op]value text
 *
 * Returns: None.
 */
static void parse_field(struct rule *rule, const char *arg)
{
	char *name = NULL;
	char *op = NULL;
	char *value = NULL;
	char *canonical = NULL;
	char *normalized = NULL;
	const char *field_name;
	int id;

	if (split_operator(arg, &name, &op, &value) < 0) {
		rule_error(rule, "field '%s' needs an operator and value", arg);
		return;
	}
	id = audit_name_to_field(name);
	if (id < 0) {
		rule_error(rule, "unknown field '%s'", name);
		goto out;
	}
	field_name = audit_field_to_name(id);
	if (field_name == NULL)
		field_name = name;
	canonical = xstrdup(field_name);
	if (!field_operator_valid(id, op)) {
		rule_error(rule, "operator '%s' is not valid for field '%s'",
			   op, canonical);
		goto out;
	}
	if (id == AUDIT_FILTERKEY) {
		if (strcmp(op, "=") != 0) {
			rule_error(rule, "key only supports '='");
			goto out;
		}
		rule_add_key(rule, value);
		goto out;
	}
	if (id == AUDIT_WATCH || id == AUDIT_DIR)
		normalized = trim_path(value);
	else if (id == AUDIT_PERM) {
		int bits = perm_bits(value);
		if (bits < 0) {
			rule_error(rule, "permission '%s' must use r, w, x, a",
				   value);
			goto out;
		}
		normalized = xstrdup(perm_string(bits));
	} else
		normalized = xstrdup(value);
	rule_add_field(rule, canonical, id, op, normalized);
out:
	free(name);
	free(op);
	free(value);
	free(canonical);
	free(normalized);
}

/*
 * parse_compare - parse and append one -C interfield comparison
 * @rule: destination rule
 * @arg: field1[op]field2 text
 *
 * Returns: None.
 */
static void parse_compare(struct rule *rule, const char *arg)
{
	char *left = NULL;
	char *right = NULL;
	char *op = NULL;
	const char *left_name;
	const char *right_name;
	int left_id;
	int right_id;

	if (split_operator(arg, &left, &op, &right) < 0 ||
	    (strcmp(op, "=") != 0 && strcmp(op, "!=") != 0)) {
		rule_error(rule, "interfield comparison '%s' must use = or !=",
			   arg);
		goto out;
	}
	left_id = audit_name_to_field(left);
	right_id = audit_name_to_field(right);
	if (left_id < 0) {
		rule_error(rule, "unknown comparison field '%s'", left);
		goto out;
	}
	if (right_id < 0) {
		rule_error(rule, "unknown comparison field '%s'", right);
		goto out;
	}
	left_name = audit_field_to_name(left_id);
	right_name = audit_field_to_name(right_id);
	rule_add_compare(rule, left_name ? left_name : left, left_id, op,
			 right_name ? right_name : right, right_id);
out:
	free(left);
	free(op);
	free(right);
}

/*
 * parse_syscalls - split and append a -S argument
 * @rule: destination rule
 * @arg: comma-separated syscall list
 *
 * Returns: None.
 */
static void parse_syscalls(struct rule *rule, const char *arg)
{
	char *copy = xstrdup(arg);
	char *saved = NULL;
	char *token;

	token = strtok_r(copy, ",", &saved);
	if (token == NULL || *token == '\0') {
		rule_error(rule, "empty syscall list");
		free(copy);
		return;
	}
	while (token != NULL) {
		if (*token == '\0')
			rule_error(rule, "empty syscall name");
		else
			rule_add_syscall(rule, token);
		token = strtok_r(NULL, ",", &saved);
	}
	free(copy);
}

/*
 * field_is_numeric - identify fields that support numeric comparisons
 * @id: audit field id
 *
 * Returns: True when numeric ordering is meaningful.
 */
static bool field_is_numeric(int id)
{
	switch (id) {
	case AUDIT_PID:
	case AUDIT_PPID:
	case AUDIT_UID:
	case AUDIT_EUID:
	case AUDIT_SUID:
	case AUDIT_FSUID:
	case AUDIT_LOGINUID:
	case AUDIT_OBJ_UID:
	case AUDIT_GID:
	case AUDIT_EGID:
	case AUDIT_SGID:
	case AUDIT_FSGID:
	case AUDIT_OBJ_GID:
	case AUDIT_SESSIONID:
	case AUDIT_DEVMAJOR:
	case AUDIT_DEVMINOR:
	case AUDIT_INODE:
	case AUDIT_EXIT:
	case AUDIT_SUCCESS:
	case AUDIT_ARG0:
	case AUDIT_ARG1:
	case AUDIT_ARG2:
	case AUDIT_ARG3:
	case AUDIT_SADDR_FAM:
		return true;
	default:
		return false;
	}
}

/*
 * field_is_unsigned - identify unsigned identity fields
 * @id: audit field id
 *
 * Returns: True for UID/GID/session fields.
 */
static bool field_is_unsigned(int id)
{
	switch (id) {
	case AUDIT_UID:
	case AUDIT_EUID:
	case AUDIT_SUID:
	case AUDIT_FSUID:
	case AUDIT_LOGINUID:
	case AUDIT_OBJ_UID:
	case AUDIT_GID:
	case AUDIT_EGID:
	case AUDIT_SGID:
	case AUDIT_FSGID:
	case AUDIT_OBJ_GID:
	case AUDIT_SESSIONID:
		return true;
	default:
		return false;
	}
}

/*
 * parse_number - convert a field value into a comparison number
 * @id: audit field id
 * @value: field value
 * @result: returned numeric value
 *
 * Returns: True when the value has numeric comparison semantics.
 */
static bool parse_number(int id, const char *value, long long *result)
{
	char *end = NULL;
	long long number;

	errno = 0;
	if (field_is_unsigned(id)) {
		if (strcmp(value, "unset") == 0) {
			*result = 4294967295LL;
			return true;
		}
	}
	if (id == AUDIT_EXIT) {
		if (!isdigit((unsigned char)value[0]) &&
		    !(value[0] == '-' &&
		      isdigit((unsigned char)value[1]))) {
			number = audit_name_to_errno(value);
			if (number != 0) {
				*result = number;
				return true;
			}
		}
	}
	if (id == AUDIT_MSGTYPE) {
		number = audit_name_to_msg_type(value);
		if (number > 0) {
			*result = number;
			return true;
		}
	}
	if (id == AUDIT_FSTYPE) {
		number = audit_name_to_fstype(value);
		if (number >= 0) {
			*result = number;
			return true;
		}
	}
	if (id == AUDIT_FILETYPE) {
		number = audit_name_to_ftype(value);
		if (number >= 0) {
			*result = number;
			return true;
		}
	}
	number = strtoll(value, &end, 0);
	if (end == value || *end != '\0' || errno == ERANGE)
		return false;
	if (field_is_unsigned(id))
		number = (long long)(unsigned int)number;
	*result = number;
	return true;
}

/*
 * compare_field_values - compare two values using field semantics
 * @id: audit field id
 * @left: first value
 * @right: second value
 *
 * Returns: -1 when unknown, 0 when equal, 1 when different.
 */
static int compare_field_values(int id, const char *left, const char *right)
{
	long long left_number;
	long long right_number;
	bool left_num;
	bool right_num;
	int left_machine;
	int right_machine;

	if (strcmp(left, right) == 0)
		return 0;
	if (id == AUDIT_ARCH) {
		left_machine = audit_determine_machine(left);
		right_machine = audit_determine_machine(right);
		if (left_machine >= 0 && right_machine >= 0) {
			unsigned int left_elf;
			unsigned int right_elf;

			left_elf = audit_machine_to_elf(left_machine);
			right_elf = audit_machine_to_elf(right_machine);
			if (left_elf != 0 && right_elf != 0)
				return left_elf == right_elf ? 0 : 1;
		}
	}
	left_num = parse_number(id, left, &left_number);
	right_num = parse_number(id, right, &right_number);
	if (left_num && right_num)
		return left_number == right_number ? 0 : 1;
	if (left_num != right_num)
		return -1;
	if (id == AUDIT_ARCH)
		return strcasecmp(left, right) == 0 ? 0 : 1;
	return 1;
}

/*
 * operator_rank - provide a stable ordering for field operators
 * @op: operator
 *
 * Returns: Sort rank.
 */
static int operator_rank(const char *op)
{
	if (strcmp(op, "=") == 0)
		return 0;
	if (strcmp(op, ">") == 0)
		return 1;
	if (strcmp(op, ">=") == 0)
		return 2;
	if (strcmp(op, "<") == 0)
		return 3;
	if (strcmp(op, "<=") == 0)
		return 4;
	if (strcmp(op, "!=") == 0)
		return 5;
	if (strcmp(op, "&") == 0)
		return 6;
	return 7;
}

/*
 * field_rank - provide a stable ordering for fields
 * @id: audit field id
 *
 * Returns: Sort rank.
 */
static int field_rank(int id)
{
	if (id == AUDIT_ARCH)
		return 0;
	if (id == AUDIT_WATCH)
		return 1;
	if (id == AUDIT_DIR)
		return 2;
	if (id == AUDIT_PERM)
		return 3;
	return 4;
}

/*
 * compare_fields - qsort callback for rule fields
 * @left: left field
 * @right: right field
 *
 * Returns: Negative, zero, or positive sort result.
 */
static int compare_fields(const void *left, const void *right)
{
	const struct rule_field *a = left;
	const struct rule_field *b = right;
	int rank_a = field_rank(a->id);
	int rank_b = field_rank(b->id);
	int rc;

	if (rank_a != rank_b)
		return rank_a - rank_b;
	rc = strcmp(a->name, b->name);
	if (rc != 0)
		return rc;
	rc = operator_rank(a->op) - operator_rank(b->op);
	if (rc != 0)
		return rc;
	return strcmp(a->value, b->value);
}

/*
 * compare_compares - qsort callback for interfield comparisons
 * @left: left comparison
 * @right: right comparison
 *
 * Returns: Negative, zero, or positive sort result.
 */
static int compare_compares(const void *left, const void *right)
{
	const struct field_compare *a = left;
	const struct field_compare *b = right;
	int rc = strcmp(a->left, b->left);

	if (rc != 0)
		return rc;
	rc = operator_rank(a->op) - operator_rank(b->op);
	if (rc != 0)
		return rc;
	return strcmp(a->right, b->right);
}

/*
 * compare_strings - qsort callback for string arrays
 * @left: left string pointer
 * @right: right string pointer
 *
 * Returns: Negative, zero, or positive sort result.
 */
static int compare_strings(const void *left, const void *right)
{
	const char * const *a = left;
	const char * const *b = right;

	return strcmp(*a, *b);
}

/*
 * normalize_rule_fields - merge duplicate fields and canonicalize perms
 * @rule: rule to normalize
 *
 * Returns: None.
 */
static void normalize_rule_fields(struct rule *rule)
{
	size_t i;
	size_t out = 0;
	int perm_mask = 0;
	bool have_perm = false;

	for (i = 0; i < rule->field_count; i++) {
		struct rule_field *field = &rule->fields[i];
		size_t j;
		bool duplicate = false;

		if (field->id == AUDIT_PERM) {
			if (have_perm) {
				perm_mask |= perm_bits(field->value);
				free(field->name);
				free(field->value);
				continue;
			}
			have_perm = true;
			perm_mask = perm_bits(field->value);
		}
		for (j = 0; j < out; j++) {
			struct rule_field *seen = &rule->fields[j];

			if (seen->id != field->id ||
			    strcmp(seen->op, field->op) != 0)
				continue;
			if (field->id == AUDIT_PERM)
				continue;
			if (strcmp(seen->value, field->value) == 0) {
				rule_warning(rule,
					     "duplicate field '%s%s%s' is redundant",
					     field->name, field->op,
					     field->value);
				free(field->name);
				free(field->value);
				duplicate = true;
				break;
			}
		}
		if (duplicate)
			continue;
		if (out != i)
			rule->fields[out] = *field;
		out++;
	}
	rule->field_count = out;
	for (i = 0; i < rule->field_count; i++) {
		if (rule->fields[i].id == AUDIT_PERM) {
			char *value = xstrdup(perm_string(perm_mask));

			free(rule->fields[i].value);
			rule->fields[i].value = value;
			break;
		}
	}
}

/*
 * duplicate_compare - check for a duplicate -C term
 * @rule: source rule
 * @index: index being checked
 *
 * Returns: True when an earlier identical comparison exists.
 */
static bool duplicate_compare(const struct rule *rule, size_t index)
{
	size_t i;

	for (i = 0; i < index; i++) {
		const struct field_compare *a = &rule->compares[i];
		const struct field_compare *b = &rule->compares[index];

		if (a->left_id == b->left_id && a->right_id == b->right_id &&
		    strcmp(a->op, b->op) == 0)
			return true;
	}
	return false;
}

/*
 * normalize_rule_compares - remove duplicate interfield comparisons
 * @rule: rule to normalize
 *
 * Returns: None.
 */
static void normalize_rule_compares(struct rule *rule)
{
	size_t i;
	size_t out = 0;

	for (i = 0; i < rule->compare_count; i++) {
		if (duplicate_compare(rule, i)) {
			rule_warning(rule,
				     "duplicate interfield comparison is redundant");
			free(rule->compares[i].left);
			free(rule->compares[i].right);
			continue;
		}
		if (out != i)
			rule->compares[out] = rule->compares[i];
		out++;
	}
	rule->compare_count = out;
	if (rule->compare_count > 1)
		qsort(rule->compares, rule->compare_count,
		      sizeof(*rule->compares), compare_compares);
}

/*
 * check_path_and_dir - reject path and dir in the same rule
 * @rule: rule to inspect
 *
 * Returns: None.
 */
static void check_path_and_dir(struct rule *rule)
{
	size_t i;
	bool path = false;
	bool dir = false;

	for (i = 0; i < rule->field_count; i++) {
		if (rule->fields[i].id == AUDIT_WATCH)
			path = true;
		if (rule->fields[i].id == AUDIT_DIR)
			dir = true;
	}
	if (path && dir)
		rule_conflict(rule,
			      "fields 'path' and 'dir' cannot be combined");
}

/*
 * check_range_conflict - validate numeric bounds for one field
 * @rule: rule being checked
 * @id: field id
 * @indices: matching field indexes
 * @count: number of matching fields
 * @pair_conflict: whether an equality conflict was already reported
 *
 * Returns: None.
 */
static void check_range_conflict(struct rule *rule, int id, size_t *indices,
				 size_t count, bool pair_conflict)
{
	bool have_low = false;
	bool have_high = false;
	bool low_inclusive = false;
	bool high_inclusive = false;
	long long low = 0;
	long long high = 0;
	size_t i;

	if (pair_conflict || !field_is_numeric(id))
		return;
	for (i = 0; i < count; i++) {
		const struct rule_field *field = &rule->fields[indices[i]];
		long long value;
		const char *op = field->op;

		if (!parse_number(id, field->value, &value))
			return;
		if (strcmp(op, "=") == 0 || strcmp(op, ">=") == 0 ||
		    strcmp(op, ">") == 0) {
			bool inclusive = strcmp(op, ">=") == 0 ||
					 strcmp(op, "=") == 0;

			if (!have_low || value > low ||
			    (value == low && !inclusive)) {
				low = value;
				low_inclusive = inclusive;
				have_low = true;
			}
		}
		if (strcmp(op, "=") == 0 || strcmp(op, "<=") == 0 ||
		    strcmp(op, "<") == 0) {
			bool inclusive = strcmp(op, "<=") == 0 ||
					 strcmp(op, "=") == 0;

			if (!have_high || value < high ||
			    (value == high && !inclusive)) {
				high = value;
				high_inclusive = inclusive;
				have_high = true;
			}
		}
	}
	if (have_low && have_high &&
	    (low > high ||
	     (low == high && !(low_inclusive && high_inclusive)) ||
	     (high - low == 1 && !low_inclusive && !high_inclusive))) {
		rule_conflict(rule,
			      "field '%s' has an empty numeric range (%lld .. %lld)",
			      rule->fields[indices[0]].name, low, high);
		return;
	}
	for (i = 0; i < count; i++) {
		const struct rule_field *field = &rule->fields[indices[i]];
		long long value;

		if (strcmp(field->op, "!=") != 0)
			continue;
		if (!parse_number(id, field->value, &value))
			continue;
		if (have_low && have_high && low == high && value == low)
			rule_conflict(rule,
				      "field '%s' cannot be both %lld and not %lld",
				      field->name, low, value);
	}
}

/*
 * check_field_conflicts - detect contradictory terms within a rule
 * @rule: rule to inspect
 *
 * Returns: None.
 */
static void check_field_conflicts(struct rule *rule)
{
	size_t i;
	size_t *indices = xmalloc((rule->field_count ?
				  rule->field_count : 1) * sizeof(*indices));
	bool *seen = xmalloc((rule->field_count ?
			      rule->field_count : 1) * sizeof(*seen));

	memset(seen, 0, (rule->field_count ? rule->field_count : 1) *
	       sizeof(*seen));
	for (i = 0; i < rule->field_count; i++) {
		size_t j;
		size_t count = 0;
		bool pair_conflict = false;

		if (seen[i])
			continue;
		for (j = i; j < rule->field_count; j++) {
			if (rule->fields[j].id == rule->fields[i].id) {
				indices[count++] = j;
				seen[j] = true;
			}
		}
		for (j = 0; j < count; j++) {
			size_t k;

			for (k = j + 1; k < count; k++) {
				const struct rule_field *a =
					&rule->fields[indices[j]];
				const struct rule_field *b =
					&rule->fields[indices[k]];
				int cmp;

				if (a->id == AUDIT_PERM)
					continue;
				if ((strcmp(a->op, "=") == 0 &&
				     strcmp(b->op, "=") == 0) ||
				    (strcmp(a->op, "=") == 0 &&
				     strcmp(b->op, "!=") == 0) ||
				    (strcmp(a->op, "!=") == 0 &&
				     strcmp(b->op, "=") == 0)) {
					cmp = compare_field_values(a->id,
								   a->value,
								   b->value);
					if (cmp == 1) {
						rule_conflict(rule,
						     "field '%s' has conflicting values '%s%s%s' and '%s%s%s'",
						     a->name, a->name, a->op,
						     a->value, b->name, b->op,
						     b->value);
						pair_conflict = true;
					}
				}
				if ((strcmp(a->op, "&") == 0 ||
				     strcmp(a->op, "&=") == 0) &&
				    strcmp(b->op, "=") == 0) {
					long long mask;
					long long value;

					if (parse_number(a->id, a->value,
							 &mask) &&
					    parse_number(a->id, b->value,
							 &value)) {
						if (strcmp(a->op, "&") == 0) {
							if ((value & mask) == 0)
								pair_conflict = true;
						} else if ((value & mask) !=
							   mask)
							pair_conflict = true;
						if (pair_conflict)
							rule_conflict(rule,
							     "field '%s' has bitmask/value conflict '%s%s%s' and '%s%s%s'",
							     a->name, a->name,
							     a->op, a->value,
							     b->name, b->op,
							     b->value);
					}
				}
				if (strcmp(a->op, "=") == 0 &&
				    (strcmp(b->op, "&") == 0 ||
				     strcmp(b->op, "&=") == 0)) {
					long long mask;
					long long value;

					if (parse_number(b->id, b->value,
							 &mask) &&
					    parse_number(a->id, a->value,
							 &value)) {
						bool bad = false;

						if (strcmp(b->op, "&") == 0) {
							if ((value & mask) == 0)
								bad = true;
						} else if ((value & mask) !=
							   mask)
							bad = true;
						if (bad) {
							pair_conflict = true;
							rule_conflict(rule,
							     "field '%s' has bitmask/value conflict '%s%s%s' and '%s%s%s'",
							     a->name, a->name,
							     a->op, a->value,
							     b->name, b->op,
							     b->value);
						}
					}
				}
			}
		}
		check_range_conflict(rule, rule->fields[i].id, indices, count,
				     pair_conflict);
	}
	free(indices);
	free(seen);
}

/*
 * find_equal_value - find the first equality value for a field
 * @rule: source rule
 * @id: field id
 *
 * Returns: Field value pointer or NULL.
 */
static const char *find_equal_value(const struct rule *rule, int id)
{
	size_t i;

	for (i = 0; i < rule->field_count; i++) {
		if (rule->fields[i].id == id &&
		    strcmp(rule->fields[i].op, "=") == 0)
			return rule->fields[i].value;
	}
	return NULL;
}

/*
 * check_compare_conflicts - validate -C terms against each other and fields
 * @rule: rule to inspect
 *
 * Returns: None.
 */
static void check_compare_conflicts(struct rule *rule)
{
	size_t i;

	for (i = 0; i < rule->compare_count; i++) {
		const struct field_compare *comp = &rule->compares[i];
		const char *left_value;
		const char *right_value;

		if (comp->left_id == comp->right_id) {
			if (strcmp(comp->op, "!=") == 0)
				rule_conflict(rule,
				      "interfield comparison '%s!=%s' can never match",
				      comp->left, comp->right);
			else
				rule_warning(rule,
				      "interfield comparison '%s=%s' is a tautology",
				      comp->left, comp->right);
			continue;
		}
		left_value = find_equal_value(rule, comp->left_id);
		right_value = find_equal_value(rule, comp->right_id);
		if (left_value && right_value) {
			int cmp = compare_field_values(comp->left_id,
						       left_value,
						       right_value);

			if ((strcmp(comp->op, "=") == 0 && cmp == 1) ||
			    (strcmp(comp->op, "!=") == 0 && cmp == 0))
				rule_conflict(rule,
				      "interfield comparison '%s%s%s' conflicts with constant values",
				      comp->left, comp->op, comp->right);
		}
	}
	for (i = 0; i < rule->compare_count; i++) {
		size_t j;

		for (j = i + 1; j < rule->compare_count; j++) {
			const struct field_compare *a = &rule->compares[i];
			const struct field_compare *b = &rule->compares[j];

			if (a->left_id == b->left_id &&
			    a->right_id == b->right_id &&
			    strcmp(a->op, b->op) != 0)
				rule_conflict(rule,
				      "interfield comparisons '%s%s%s' and '%s%s%s' conflict",
				      a->left, a->op, a->right, b->left,
				      b->op, b->right);
		}
	}
}

/*
 * field_allowed_for_list - validate a field against its rule list
 * @rule: destination rule
 * @field: field to validate
 *
 * Returns: True when the field is valid for the list.
 */
static bool field_allowed_for_list(struct rule *rule,
				   const struct rule_field *field)
{
	int id = field->id;
	const char *list = rule->list;

	if (list == NULL)
		return true;
	if (strcmp(list, "exit") == 0) {
		if (id == AUDIT_FSTYPE) {
			rule_conflict(rule,
			      "field 'fstype' is only valid on the filesystem list");
			return false;
		}
		if (id == AUDIT_MSGTYPE) {
			rule_conflict(rule,
			      "field 'msgtype' is only valid on the exclude or user list");
			return false;
		}
		return true;
	}
	if (strcmp(list, "filesystem") == 0) {
		if (id != AUDIT_FSTYPE) {
			rule_conflict(rule,
			      "field '%s' is not valid on the filesystem list",
			      field->name);
			return false;
		}
		return true;
	}
	if (strcmp(list, "task") == 0) {
		switch (id) {
		case AUDIT_EXIT:
		case AUDIT_SUCCESS:
		case AUDIT_WATCH:
		case AUDIT_DIR:
		case AUDIT_PERM:
		case AUDIT_FILETYPE:
		case AUDIT_FSTYPE:
		case AUDIT_DEVMAJOR:
		case AUDIT_DEVMINOR:
		case AUDIT_INODE:
			rule_conflict(rule,
			      "field '%s' is not valid on the task list",
			      field->name);
			return false;
		default:
			return true;
		}
	}
	if (strcmp(list, "user") == 0) {
		switch (id) {
		case AUDIT_EXIT:
		case AUDIT_SUCCESS:
		case AUDIT_WATCH:
		case AUDIT_DIR:
		case AUDIT_PERM:
		case AUDIT_FILETYPE:
		case AUDIT_FSTYPE:
		case AUDIT_DEVMAJOR:
		case AUDIT_DEVMINOR:
		case AUDIT_INODE:
			rule_conflict(rule,
			      "field '%s' is not valid on the user list",
			      field->name);
			return false;
		default:
			return true;
		}
	}
	if (strcmp(list, "exclude") == 0) {
		switch (id) {
		case AUDIT_EXIT:
		case AUDIT_SUCCESS:
		case AUDIT_WATCH:
		case AUDIT_DIR:
		case AUDIT_PERM:
		case AUDIT_FILETYPE:
		case AUDIT_FSTYPE:
		case AUDIT_DEVMAJOR:
		case AUDIT_DEVMINOR:
		case AUDIT_INODE:
			rule_conflict(rule,
			      "field '%s' is not valid on the exclude list",
			      field->name);
			return false;
		default:
			return true;
		}
	}
	if (strcmp(list, "io_uring") == 0 && id == AUDIT_ARCH) {
		rule_conflict(rule,
			      "field 'arch' is implicit on the io_uring list");
		return false;
	}
	return true;
}

/*
 * validate_rule_context - check list/action/syscall combinations
 * @rule: rule to validate
 *
 * Returns: None.
 */
static void validate_rule_context(struct rule *rule)
{
	size_t i;

	if (rule->kind == RULE_WATCH || rule->kind == RULE_REMOVE_WATCH)
		return;
	if (rule->action == NULL || rule->list == NULL)
		return;
	if (rule->arch_after_syscall)
		rule_conflict(rule,
			      "field 'arch' must appear before -S");
	if ((rule->syscall_count > 0 || rule->explicit_all) &&
	    strcmp(rule->list, "exit") != 0 &&
	    strcmp(rule->list, "io_uring") != 0)
		rule_conflict(rule,
			      "syscalls are not valid on the %s list",
			      rule->list);
	for (i = 0; i < rule->field_count; i++)
		field_allowed_for_list(rule, &rule->fields[i]);
	if (rule->compare_count > 0 && strcmp(rule->list, "exit") != 0)
		rule_conflict(rule,
			      "interfield comparisons are only valid on the exit list");
}

/*
 * normalize_rule - canonicalize field order, masks, and all-syscall state
 * @rule: rule to normalize
 *
 * Returns: None.
 */
static void normalize_rule(struct rule *rule)
{
	if (rule->explicit_all) {
		size_t i;

		for (i = 0; i < rule->syscall_count; i++)
			free(rule->syscalls[i]);
		rule->syscall_count = 0;
		rule->all = true;
	}
	normalize_rule_fields(rule);
	normalize_rule_compares(rule);
	if (rule->syscall_count > 1)
		qsort(rule->syscalls, rule->syscall_count,
		      sizeof(*rule->syscalls), compare_strings);
	if (rule->key_count > 1)
		qsort(rule->keys, rule->key_count, sizeof(*rule->keys),
		      compare_strings);
	if (rule->field_count > 1)
		qsort(rule->fields, rule->field_count, sizeof(*rule->fields),
		      compare_fields);
	if (rule->kind == RULE_SYSCALL && !rule->all &&
	    rule->syscall_count == 0 && !rule->has_perm &&
	    rule->list != NULL &&
	    (strcmp(rule->list, "exit") == 0 ||
	     strcmp(rule->list, "io_uring") == 0))
		rule->all = true;
}

/*
 * same_fields - compare two canonical field arrays
 * @left: left rule
 * @right: right rule
 *
 * Returns: True when all fields match.
 */
static bool same_fields(const struct rule *left, const struct rule *right)
{
	size_t i;

	if (left->field_count != right->field_count)
		return false;
	for (i = 0; i < left->field_count; i++) {
		const struct rule_field *a = &left->fields[i];
		const struct rule_field *b = &right->fields[i];

		if (a->id != b->id || strcmp(a->op, b->op) != 0 ||
		    strcmp(a->value, b->value) != 0)
			return false;
	}
	return true;
}

/*
 * same_compares - compare two canonical comparison arrays
 * @left: left rule
 * @right: right rule
 *
 * Returns: True when all comparisons match.
 */
static bool same_compares(const struct rule *left, const struct rule *right)
{
	size_t i;

	if (left->compare_count != right->compare_count)
		return false;
	for (i = 0; i < left->compare_count; i++) {
		const struct field_compare *a = &left->compares[i];
		const struct field_compare *b = &right->compares[i];

		if (a->left_id != b->left_id || a->right_id != b->right_id ||
		    strcmp(a->op, b->op) != 0)
			return false;
	}
	return true;
}

/*
 * same_strings - compare two sorted string arrays
 * @left: left array
 * @left_count: left element count
 * @right: right array
 * @right_count: right element count
 *
 * Returns: True when both arrays match.
 */
static bool same_strings(char **left, size_t left_count, char **right,
			 size_t right_count)
{
	size_t i;

	if (left_count != right_count)
		return false;
	for (i = 0; i < left_count; i++) {
		if (strcmp(left[i], right[i]) != 0)
			return false;
	}
	return true;
}

/*
 * same_rule_body - compare everything except syscall masks
 * @left: left rule
 * @right: right rule
 *
 * Returns: True when the non-syscall bodies match.
 */
static bool same_rule_body(const struct rule *left, const struct rule *right)
{
	if (left->kind != right->kind || left->directive != right->directive)
		return false;
	if (left->kind == RULE_WATCH || left->kind == RULE_REMOVE_WATCH) {
		if (strcmp(left->path, right->path) != 0)
			return false;
		if (left->kind == RULE_WATCH &&
		    strcmp(left->perm, right->perm) != 0)
			return false;
		return same_strings(left->keys, left->key_count, right->keys,
				    right->key_count);
	}
	if (strcmp(left->action, right->action) != 0 ||
	    strcmp(left->list, right->list) != 0)
		return false;
	if (left->all != right->all)
		return false;
	if (!same_fields(left, right) || !same_compares(left, right))
		return false;
	return same_strings(left->keys, left->key_count, right->keys,
			    right->key_count);
}

/*
 * same_rule - compare two complete canonical rules
 * @left: left rule
 * @right: right rule
 *
 * Returns: True when both rules are identical.
 */
static bool same_rule(const struct rule *left, const struct rule *right)
{
	if (!same_rule_body(left, right))
		return false;
	if (left->kind != RULE_SYSCALL)
		return true;
	if (left->all)
		return true;
	return same_strings(left->syscalls, left->syscall_count,
			    right->syscalls, right->syscall_count);
}

/*
 * rules_can_merge - check whether two rules have mergeable bodies
 * @left: left rule
 * @right: right rule
 *
 * Returns: True when only syscall masks or watch permissions differ.
 */
static bool rules_can_merge(const struct rule *left, const struct rule *right)
{
	if (left->kind != right->kind || left->directive != right->directive)
		return false;
	if (left->kind == RULE_SYSCALL)
		return same_fields(left, right) &&
		       same_compares(left, right) &&
		       strcmp(left->action, right->action) == 0 &&
		       strcmp(left->list, right->list) == 0 &&
		       same_strings(left->keys, left->key_count, right->keys,
				    right->key_count);
	if (left->kind == RULE_WATCH)
		return strcmp(left->path, right->path) == 0 &&
		       same_strings(left->keys, left->key_count, right->keys,
				    right->key_count);
	return false;
}

/*
 * merge_syscalls - union a syscall mask into another rule
 * @target: destination rule
 * @source: source rule
 *
 * Returns: None.
 */
static void merge_syscalls(struct rule *target, const struct rule *source)
{
	size_t i;

	if (target->all || source->all) {
		for (i = 0; i < target->syscall_count; i++)
			free(target->syscalls[i]);
		target->syscall_count = 0;
		target->all = true;
		target->explicit_all = target->explicit_all ||
				       source->explicit_all;
		return;
	}
	for (i = 0; i < source->syscall_count; i++) {
		size_t j;
		bool present = false;

		for (j = 0; j < target->syscall_count; j++) {
			if (strcmp(target->syscalls[j],
				   source->syscalls[i]) == 0) {
				present = true;
				break;
			}
		}
		if (!present)
			rule_add_syscall(target, source->syscalls[i]);
	}
	if (target->syscall_count > 1)
		qsort(target->syscalls, target->syscall_count,
		      sizeof(*target->syscalls), compare_strings);
}

/*
 * merge_watch_perms - union watch permissions
 * @target: destination rule
 * @source: source rule
 *
 * Returns: None.
 */
static void merge_watch_perms(struct rule *target, const struct rule *source)
{
	int bits = perm_bits(target->perm) | perm_bits(source->perm);

	free(target->perm);
	target->perm = xstrdup(perm_string(bits));
}

/*
 * detect_duplicates - mark later copies of identical rules
 *
 * Returns: None.
 */
static void detect_duplicates(void)
{
	size_t i;
	size_t j;

	for (i = 0; i < g_rule_count; i++) {
		struct rule *rule = g_rules[i];

		if (rule->removed || rule->has_error)
			continue;
		for (j = 0; j < i; j++) {
			struct rule *first = g_rules[j];

			if (first->removed || first->has_error)
				continue;
			if (!same_rule(first, rule))
				continue;
			g_duplicates++;
			g_errors++;
			rule->removed = true;
			if (!g_quiet)
				fprintf(stderr,
					"%s:%d: error: duplicate rule (first defined at %s:%d)\n",
					rule->file, rule->line, first->file,
					first->line);
			break;
		}
	}
}

/*
 * minimize_rules - merge duplicate bodies and watch permission sets
 *
 * Returns: Number of rules removed by merging.
 */
static size_t minimize_rules(void)
{
	size_t i;
	size_t j;
	size_t merged = 0;

	if (!g_minimize)
		return 0;
	for (i = 0; i < g_rule_count; i++) {
		struct rule *target = g_rules[i];

		if (target->removed || target->has_error ||
		    target->kind == RULE_REMOVE_WATCH)
			continue;
		for (j = i + 1; j < g_rule_count; j++) {
			struct rule *source = g_rules[j];

			if (source->removed || source->has_error)
				continue;
			if (!rules_can_merge(target, source))
				continue;
			if (target->kind == RULE_SYSCALL)
				merge_syscalls(target, source);
			else
				merge_watch_perms(target, source);
			source->removed = true;
			merged++;
		}
	}
	return merged;
}

/*
 * validate_rule - run all rule-level validation
 * @rule: rule to validate
 *
 * Returns: None.
 */
static void validate_rule(struct rule *rule)
{
	if (rule->kind == RULE_WATCH || rule->kind == RULE_REMOVE_WATCH) {
		if (rule->path == NULL || rule->path[0] != '/')
			rule_error(rule, "watch path must be absolute");
		if (rule->field_count || rule->compare_count ||
		    rule->syscall_count) {
			rule_conflict(rule,
				      "watches may not include -F, -C, or -S terms");
		}
		if (rule->kind == RULE_WATCH && rule->perm == NULL)
			rule->perm = xstrdup("rwxa");
		return;
	}
	validate_rule_context(rule);
	check_path_and_dir(rule);
	check_field_conflicts(rule);
	check_compare_conflicts(rule);
}

/*
 * tokenize_line - split an audit rules line using auditctl escaping
 * @line: source line
 * @count: returned token count
 *
 * Returns: Newly allocated token array.
 */
static char **tokenize_line(const char *line, size_t *count)
{
	char **tokens = NULL;
	size_t token_count = 0;
	size_t token_alloc = 0;
	const char *ptr = line;

	while (*ptr) {
		struct strbuf token;

		while (isspace((unsigned char)*ptr))
			ptr++;
		if (*ptr == '\0')
			break;
		sb_init(&token);
		while (*ptr && !isspace((unsigned char)*ptr)) {
			if (*ptr == '\\' && ptr[1] != '\0' &&
			    (ptr[1] == ' ' || ptr[1] == '\\')) {
				sb_putc(&token, ptr[1]);
				ptr += 2;
				continue;
			}
			sb_putc(&token, *ptr++);
		}
		if (token_count == token_alloc) {
			token_alloc = token_alloc ? token_alloc * 2 : 8;
			tokens = xrealloc(tokens,
					  token_alloc * sizeof(*tokens));
		}
		tokens[token_count++] = token.data;
	}
	*count = token_count;
	return tokens;
}

/*
 * free_tokens - release a token array
 * @tokens: token array
 * @count: number of tokens
 *
 * Returns: None.
 */
static void free_tokens(char **tokens, size_t count)
{
	size_t i;

	if (tokens == NULL)
		return;
	for (i = 0; i < count; i++)
		free(tokens[i]);
	free(tokens);
}

/*
 * parse_watch - parse a -w or -W directive
 * @rule: destination rule
 * @tokens: token array
 * @count: token count
 *
 * Returns: None.
 */
static void parse_watch(struct rule *rule, char **tokens, size_t count)
{
	size_t i;
	int perm = 0;
	bool have_perm = false;

	if (count < 2) {
		rule_error(rule, "%s needs a path", tokens[0]);
		return;
	}
	rule->path = trim_path(tokens[1]);
	if (rule->path[0] != '/')
		rule_error(rule, "watch path must start with '/'");
	if (strstr(rule->path, ".."))
		rule_warning(rule, "relative path notation is not supported");
	if (strchr(rule->path, '*') || strchr(rule->path, '?'))
		rule_warning(rule, "wildcard notation is not supported");
	for (i = 2; i < count; i++) {
		if (strcmp(tokens[i], "-p") == 0) {
			int bits;

			i++;
			if (i >= count) {
				rule_error(rule, "-p needs a permission set");
				continue;
			}
			bits = perm_bits(tokens[i]);
			if (bits < 0) {
				rule_error(rule,
					   "permission '%s' must use r, w, x, a",
					   tokens[i]);
				continue;
			}
			perm |= bits;
			have_perm = true;
		} else if (strcmp(tokens[i], "-k") == 0) {
			i++;
			if (i >= count)
				rule_error(rule, "-k needs a key");
			else
				rule_add_key(rule, tokens[i]);
		} else if (strcmp(tokens[i], "-F") == 0) {
			char *name = NULL;
			char *op = NULL;
			char *value = NULL;

			if (i + 1 >= count) {
				rule_error(rule, "-F needs field=value");
				continue;
			}
			i++;
			if (split_operator(tokens[i], &name, &op, &value) == 0 &&
			    strcmp(name, "key") == 0 &&
			    strcmp(op, "=") == 0)
				rule_add_key(rule, value);
			else
				rule_conflict(rule,
					      "watches may not include -F terms other than key=");
			free(name);
			free(op);
			free(value);
		} else if (strcmp(tokens[i], "-C") == 0 ||
			   strcmp(tokens[i], "-S") == 0) {
			rule_conflict(rule,
				      "watches may not include %s terms",
				      tokens[i]);
			if (i + 1 < count)
				i++;
		} else {
			rule_error(rule,
				   "watches only accept -p and -k, not '%s'",
				   tokens[i]);
		}
	}
	if (rule->kind == RULE_WATCH)
		rule->perm = xstrdup(have_perm ? perm_string(perm) : "rwxa");
	else if (have_perm)
		rule_warning(rule, "-p is ignored for -W");
}

/*
 * parse_rule - parse an -a, -A, -d, -w, or -W directive
 * @file: source file
 * @line: source line
 * @tokens: token array
 * @count: token count
 *
 * Returns: Parsed rule.
 */
static struct rule *parse_rule(const char *file, int line, char **tokens,
			       size_t count)
{
	struct rule *rule;
	enum rule_kind kind;
	size_t i;

	if (strcmp(tokens[0], "-w") == 0)
		kind = RULE_WATCH;
	else if (strcmp(tokens[0], "-W") == 0)
		kind = RULE_REMOVE_WATCH;
	else
		kind = RULE_SYSCALL;
	rule = new_rule(kind, tokens[0][1], file, line);
	if (kind == RULE_WATCH || kind == RULE_REMOVE_WATCH) {
		parse_watch(rule, tokens, count);
		normalize_rule(rule);
		validate_rule(rule);
		return rule;
	}
	if (count < 2 || parse_action_list(rule, tokens[1]) < 0) {
		if (count < 2)
			rule_error(rule, "%s needs action,list", tokens[0]);
		normalize_rule(rule);
		validate_rule(rule);
		return rule;
	}
	for (i = 2; i < count; i++) {
		const char *token = tokens[i];

		if (strcmp(token, "-S") == 0) {
			i++;
			if (i >= count)
				rule_error(rule, "-S needs a syscall");
			else
				parse_syscalls(rule, tokens[i]);
		} else if (strcmp(token, "-F") == 0) {
			size_t field_count = rule->field_count;

			i++;
			if (i >= count)
				rule_error(rule, "-F needs field=value");
			else {
				parse_field(rule, tokens[i]);
				if (rule->field_count > field_count &&
				    rule->fields[rule->field_count - 1].id ==
				    AUDIT_ARCH &&
				    (rule->syscall_count > 0 ||
				     rule->explicit_all))
					rule->arch_after_syscall = true;
			}
		} else if (strcmp(token, "-C") == 0) {
			i++;
			if (i >= count)
				rule_error(rule, "-C needs field=field");
			else
				parse_compare(rule, tokens[i]);
		} else if (strcmp(token, "-k") == 0) {
			i++;
			if (i >= count)
				rule_error(rule, "-k needs a key");
			else
				rule_add_key(rule, tokens[i]);
		} else if (strcmp(token, "-p") == 0) {
			rule_error(rule,
				   "-p is only valid with -w or -W; use -F perm=");
		} else {
			rule_error(rule, "unexpected option '%s'", token);
		}
	}
	normalize_rule(rule);
	validate_rule(rule);
	return rule;
}

/*
 * is_control - validate a standalone control directive
 * @tokens: token array
 * @count: token count
 * @file: source file
 * @line: source line
 *
 * Returns: True when the line is a valid control directive.
 */
static bool is_control(char **tokens, size_t count, const char *file, int line)
{
	const char *cmd = tokens[0];
	bool needs_numeric = false;
	bool no_args = false;
	bool one_arg = false;

	if (strcmp(cmd, "-D") == 0 || strcmp(cmd, "-c") == 0 ||
	    strcmp(cmd, "-i") == 0 || strcmp(cmd, "-t") == 0 ||
	    strcmp(cmd, "--loginuid-immutable") == 0 ||
	    strcmp(cmd, "--reset-lost") == 0 ||
	    strcmp(cmd, "--reset_backlog_wait_time_actual") == 0)
		no_args = true;
	else if (strcmp(cmd, "-b") == 0 || strcmp(cmd, "-e") == 0 ||
		 strcmp(cmd, "-f") == 0 || strcmp(cmd, "-r") == 0)
		needs_numeric = true;
	else if (strcmp(cmd, "-q") == 0 || strcmp(cmd, "-m") == 0 ||
		 strcmp(cmd, "--backlog_wait_time") == 0 ||
		 strcmp(cmd, "--signal") == 0)
		one_arg = true;
	else {
		diag_error(file, line, "unknown directive '%s'", cmd);
		return false;
	}
	if (no_args && count != 1) {
		diag_error(file, line, "%s does not take arguments", cmd);
		return false;
	}
	if ((needs_numeric || one_arg) && count != 2) {
		diag_error(file, line, "%s needs exactly one argument", cmd);
		return false;
	}
	if (needs_numeric) {
		char *end = NULL;
		long value;

		errno = 0;
		value = strtol(tokens[1], &end, 0);
		if (end == tokens[1] || *end != '\0' || errno == ERANGE ||
		    value < 0) {
			diag_error(file, line, "%s needs a non-negative number",
				   cmd);
			return false;
		}
		if ((strcmp(cmd, "-e") == 0 || strcmp(cmd, "-f") == 0) &&
		    value > 2) {
			diag_error(file, line, "%s must be 0, 1, or 2", cmd);
			return false;
		}
	}
	if (strcmp(cmd, "-q") == 0 && strchr(tokens[1], ',') == NULL) {
		diag_error(file, line, "-q needs mount,subtree");
		return false;
	}
	return true;
}

/*
 * control_text - canonicalize a control directive
 * @tokens: token array
 * @count: token count
 *
 * Returns: Newly allocated normalized text.
 */
static char *control_text(char **tokens, size_t count)
{
	struct strbuf sb;
	size_t i;

	sb_init(&sb);
	for (i = 0; i < count; i++) {
		if (i)
			sb_putc(&sb, ' ');
		sb_escape(&sb, tokens[i]);
	}
	return sb.data;
}

/*
 * parse_line - parse one audit.rules line
 * @file: source file
 * @line: source line
 * @text: line text without newline
 *
 * Returns: None.
 */
static void parse_line(const char *file, int line, const char *text)
{
	const char *ptr = text;
	char **tokens;
	size_t count;

	while (isspace((unsigned char)*ptr))
		ptr++;
	if (*ptr == '\0')
		return;
	if (*ptr == '#') {
		add_item(ITEM_COMMENT, NULL, xstrdup(ptr), file, line);
		return;
	}
	tokens = tokenize_line(text, &count);
	if (count == 0) {
		free_tokens(tokens, count);
		return;
	}
	if (strcmp(tokens[0], "-a") == 0 || strcmp(tokens[0], "-A") == 0 ||
	    strcmp(tokens[0], "-d") == 0 || strcmp(tokens[0], "-w") == 0 ||
	    strcmp(tokens[0], "-W") == 0) {
		struct rule *rule = parse_rule(file, line, tokens, count);

		add_rule_ptr(rule);
		add_item(ITEM_RULE, rule, NULL, file, line);
	} else if (is_control(tokens, count, file, line)) {
		add_item(ITEM_CONTROL, NULL, control_text(tokens, count),
			 file, line);
	}
	free_tokens(tokens, count);
}

/*
 * parse_file - read and parse one rules file
 * @path: file path, or "-" for standard input
 *
 * Returns: Zero on success, nonzero on I/O failure.
 */
static int parse_file(const char *path)
{
	FILE *file;
	char *line = NULL;
	size_t line_alloc = 0;
	ssize_t len;
	int line_number = 0;
	int ret = 0;
	const char *name = path;

	if (strcmp(path, "-") == 0) {
		file = stdin;
		name = "<stdin>";
	} else {
		file = fopen(path, "r");
		if (file == NULL) {
			fprintf(stderr,
				"audit-rule-compiler: cannot open %s: %s\n",
				path, strerror(errno));
			return 1;
		}
	}
	while ((len = getline(&line, &line_alloc, file)) >= 0) {
		line_number++;
		while (len > 0 &&
		       (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		parse_line(name, line_number, line);
	}
	if (ferror(file)) {
		fprintf(stderr, "audit-rule-compiler: error reading %s: %s\n",
			name, strerror(errno));
		ret = 1;
	}
	free(line);
	if (file != stdin)
		fclose(file);
	return ret;
}

/*
 * output_rule - write one canonical rule
 * @sb: output string builder
 * @rule: rule to write
 *
 * Returns: None.
 */
static void output_rule(struct strbuf *sb, const struct rule *rule)
{
	size_t i;

	if (rule->kind == RULE_WATCH || rule->kind == RULE_REMOVE_WATCH) {
		sb_printf(sb, "-%c ", rule->directive);
		sb_escape(sb, rule->path);
		if (rule->kind == RULE_WATCH && rule->perm) {
			sb_puts(sb, " -p ");
			sb_puts(sb, rule->perm);
		}
		for (i = 0; i < rule->key_count; i++) {
			sb_puts(sb, " -k ");
			sb_escape(sb, rule->keys[i]);
		}
		sb_putc(sb, '\n');
		return;
	}
	sb_printf(sb, "-%c %s,%s", rule->directive, rule->action,
		  rule->list);
	for (i = 0; i < rule->field_count; i++) {
		const struct rule_field *field = &rule->fields[i];

		sb_puts(sb, " -F ");
		sb_escape(sb, field->name);
		sb_puts(sb, field->op);
		sb_escape(sb, field->value);
	}
	for (i = 0; i < rule->compare_count; i++) {
		const struct field_compare *comp = &rule->compares[i];

		sb_puts(sb, " -C ");
		sb_escape(sb, comp->left);
		sb_puts(sb, comp->op);
		sb_escape(sb, comp->right);
	}
	if (rule->all && rule->explicit_all)
		sb_puts(sb, " -S all");
	else if (rule->syscall_count > 0) {
		sb_puts(sb, " -S ");
		for (i = 0; i < rule->syscall_count; i++) {
			if (i)
				sb_putc(sb, ',');
			sb_escape(sb, rule->syscalls[i]);
		}
	}
	for (i = 0; i < rule->key_count; i++) {
		sb_puts(sb, " -k ");
		sb_escape(sb, rule->keys[i]);
	}
	sb_putc(sb, '\n');
}

/*
 * write_output - write controls, comments, and minimized rules
 * @file: output stream
 *
 * Returns: None.
 */
static void write_output(FILE *file)
{
	size_t i;

	for (i = 0; i < g_item_count; i++) {
		struct item *item = &g_items[i];

		if (item->kind == ITEM_COMMENT) {
			if (g_keep_comments) {
				fputs(item->text, file);
				fputc('\n', file);
			}
			continue;
		}
		if (item->kind == ITEM_CONTROL) {
			fputs(item->text, file);
			fputc('\n', file);
			continue;
		}
		if (item->rule->removed)
			continue;
		{
			struct strbuf sb;

			sb_init(&sb);
			output_rule(&sb, item->rule);
			fputs(sb.data, file);
			sb_free(&sb);
		}
	}
}

/*
 * usage - print command usage
 * @stream: output stream
 *
 * Returns: None.
 */
static void usage(FILE *stream)
{
	fprintf(stream,
		"usage: audit-rule-compiler [options] FILE...\n"
		"  -c, --check          validate only; do not write rules\n"
		"  -q, --quiet          suppress warnings and summary\n"
		"  -s, --strict         treat warnings as errors\n"
		"  -k, --keep-comments  retain comments in output\n"
		"  -n, --no-minimize    do not merge compatible rules\n"
		"  -f, --force          write output even when errors were found\n"
		"  -o, --output FILE    write normalized rules to FILE\n"
		"  -h, --help           show this help\n"
		"  -V, --version        show version\n");
}

/*
 * main - parse arguments, compile rules, and report diagnostics
 * @argc: argument count
 * @argv: argument vector
 *
 * Returns: Zero on success, one for rule errors, two for usage or I/O.
 */
int main(int argc, char *argv[])
{
	int option;
	int ret = 0;
	size_t i;
	size_t emitted = 0;
	size_t merged;
	bool failed;
	FILE *out = stdout;
	static const struct option long_options[] = {
		{ "check", no_argument, NULL, 'c' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "strict", no_argument, NULL, 's' },
		{ "keep-comments", no_argument, NULL, 'k' },
		{ "no-minimize", no_argument, NULL, 'n' },
		{ "force", no_argument, NULL, 'f' },
		{ "output", required_argument, NULL, 'o' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};

	while ((option = getopt_long(argc, argv, "cqsknfo:hV",
				     long_options, NULL)) != -1) {
		switch (option) {
		case 'c':
			g_check_only = true;
			break;
		case 'q':
			g_quiet = true;
			break;
		case 's':
			g_strict = true;
			break;
		case 'k':
			g_keep_comments = true;
			break;
		case 'n':
			g_minimize = false;
			break;
		case 'f':
			g_force = true;
			break;
		case 'o':
			g_output = optarg;
			break;
		case 'h':
			usage(stdout);
			return EXIT_SUCCESS;
		case 'V':
			printf("audit-rule-compiler %s\n", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		default:
			usage(stderr);
			return 2;
		}
	}
	if (optind >= argc) {
		usage(stderr);
		return 2;
	}
	for (i = (size_t)optind; i < (size_t)argc; i++) {
		if (parse_file(argv[i]) != 0)
			ret = 2;
	}
	if (ret != 0)
		goto out;
	detect_duplicates();
	merged = minimize_rules();
	failed = g_errors > 0 || (g_strict && g_warnings > 0);
	if (!g_check_only && (!failed || g_force)) {
		if (g_output != NULL && strcmp(g_output, "-") != 0) {
			out = fopen(g_output, "w");
			if (out == NULL) {
				fprintf(stderr,
					"audit-rule-compiler: cannot create %s: %s\n",
					g_output, strerror(errno));
				ret = 2;
				goto out;
			}
		}
		write_output(out);
		if (out != stdout)
			fclose(out);
	}
	for (i = 0; i < g_rule_count; i++) {
		if (!g_rules[i]->removed)
			emitted++;
	}
	if (!g_quiet) {
		fprintf(stderr,
			"audit-rule-compiler: %zu input rule(s), %zu output rule(s), %zu merged, %d conflict(s), %d duplicate(s), %d warning(s)%s\n",
			g_rule_count, emitted, merged, g_conflicts,
			g_duplicates, g_warnings,
			failed && !g_check_only && !g_force ?
			" (output suppressed)" : "");
	}
	if (failed)
		ret = 1;
out:
	for (i = 0; i < g_rule_count; i++)
		free_rule(g_rules[i]);
	free(g_rules);
	for (i = 0; i < g_item_count; i++)
		free(g_items[i].text);
	free(g_items);
	return ret;
}
