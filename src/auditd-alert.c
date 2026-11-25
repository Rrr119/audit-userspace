/* auditd-alert.c -- rule triggered real-time alerts aggregated by syscall
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "auditd-alert.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdbool.h>

#define ALERT_AGGREGATE_SIZE 1024
#define ALERT_RECORD_LIMIT (64 * 1024)

struct alert_rule {
	int used;
	struct audit_alert_rule_config config;
	char syscall_name[AUDIT_ALERT_NAME_LEN];
	char key[AUDIT_ALERT_KEY_LEN];
};

struct alert_aggregate {
	int used;
	int syscall;
	char syscall_name[AUDIT_ALERT_NAME_LEN];
	uint64_t count;
};

struct audit_alert_engine {
	struct alert_rule rules[AUDIT_ALERT_MAX_RULES];
	struct alert_aggregate aggregates[ALERT_AGGREGATE_SIZE];
	audit_alert_notify_fn notify;
	void *user_data;
	size_t rule_count;
	uint64_t total_count;
	uint64_t notification_count;
	uint64_t last_latency_ns;
	uint64_t max_latency_ns;
	uint64_t total_latency_ns;
};

/*
 * monotonic_ns - read a monotonic timestamp in nanoseconds
 *
 * Returns: Current CLOCK_MONOTONIC value, or zero if the clock is unavailable.
 */
static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;

	return (uint64_t)now.tv_sec * 1000000000ULL +
		(uint64_t)now.tv_nsec;
}

/*
 * field_offset - locate a top-level name=value field in a bounded record
 * @record: record text to scan
 * @length: number of valid bytes in @record
 * @name: field name without the equals sign
 * @value_offset: receives the offset of the first value byte
 *
 * Returns: 0 when the field is found and -ENOENT otherwise.
 */
static int field_offset(const char *record, size_t length, const char *name,
			size_t *value_offset)
{
	size_t name_len = strlen(name);
	size_t field_start = 0;

	while (field_start < length) {
		size_t equals = field_start;
		size_t next = field_start;
		bool quoted = false;

		while (equals < length && record[equals] != '=')
			equals++;
		if (equals < length && equals - field_start == name_len &&
		    strncmp(record + field_start, name, name_len) == 0) {
			*value_offset = equals + 1;
			return 0;
		}

		while (next < length) {
			if (record[next] == '\\' && next + 1 < length) {
				next += 2;
				continue;
			}
			if (record[next] == '"')
				quoted = !quoted;
			if (!quoted &&
			    (record[next] == ' ' || record[next] == '\t' ||
			     record[next] == '\n' || record[next] == '\r'))
				break;
			next++;
		}

		field_start = next;
		while (field_start < length &&
		       (record[field_start] == ' ' ||
			record[field_start] == '\t' ||
			record[field_start] == '\n' ||
			record[field_start] == '\r'))
			field_start++;
	}

	return -ENOENT;
}

/*
 * copy_field_value - copy a quoted or whitespace terminated field value
 * @dst: destination buffer
 * @dst_size: destination size in bytes
 * @record: record text
 * @length: number of valid record bytes
 * @offset: value offset returned by field_offset()
 *
 * Returns: Nothing. The destination is always NUL terminated when non-empty.
 */
static void copy_field_value(char *dst, size_t dst_size, const char *record,
			     size_t length, size_t offset)
{
	size_t begin, end, copy_len;

	if (dst_size == 0)
		return;
	dst[0] = '\0';
	if (offset >= length)
		return;

	if (record[offset] == '"') {
		begin = offset + 1;
		end = begin;
		while (end < length && record[end] != '"')
			end++;
	} else {
		begin = offset;
		end = begin;
		while (end < length && record[end] != ' ' &&
		       record[end] != '\t' && record[end] != '\n' &&
		       record[end] != '\r')
			end++;
	}

	copy_len = end - begin;
	if (copy_len >= dst_size)
		copy_len = dst_size - 1;
	memcpy(dst, record + begin, copy_len);
	dst[copy_len] = '\0';

	if (strcmp(dst, "(null)") == 0)
		dst[0] = '\0';
}

/*
 * read_field - find and copy a record field
 *
 * Returns: 0 when found and copied, or a negative errno value.
 */
static int read_field(const char *record, size_t length, const char *name,
		      char *value, size_t value_size)
{
	size_t offset;
	int rc;

	rc = field_offset(record, length, name, &offset);
	if (rc != 0)
		return rc;

	copy_field_value(value, value_size, record, length, offset);
	return 0;
}

/*
 * parse_int - parse a bounded decimal integer
 *
 * Returns: 0 on success and -EINVAL when the text is not a complete integer.
 */
static int parse_int(const char *text, int *value)
{
	char *end;
	long parsed;

	if (text == NULL || text[0] == '\0')
		return -EINVAL;

	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0')
		return -EINVAL;

	*value = (int)parsed;
	return 0;
}

/*
 * syscall_hash - hash a numeric or named syscall key
 *
 * Returns: A hash value suitable for masking to the aggregate table.
 */
static size_t syscall_hash(int syscall, const char *name)
{
	uint64_t hash = 1469598103934665603ULL;
	const unsigned char *p;

	if (syscall >= 0) {
		unsigned int value = (unsigned int)syscall + 1;

		hash ^= value & 0xff;
		hash *= 1099511628211ULL;
		hash ^= (value >> 8) & 0xff;
		hash *= 1099511628211ULL;
		hash ^= (value >> 16) & 0xff;
		hash *= 1099511628211ULL;
		hash ^= (value >> 24) & 0xff;
		hash *= 1099511628211ULL;
		return (size_t)hash;
	}

	for (p = (const unsigned char *)name; *p != '\0'; p++) {
		hash ^= *p;
		hash *= 1099511628211ULL;
	}

	return (size_t)hash;
}

/*
 * same_syscall - compare an aggregate key with a parsed syscall
 *
 * Returns: Non-zero when both keys identify the same syscall.
 */
static int same_syscall(const struct alert_aggregate *aggregate, int syscall,
			const char *name)
{
	if (syscall >= 0)
		return aggregate->syscall == syscall;

	return aggregate->syscall < 0 && name != NULL &&
	       strcmp(aggregate->syscall_name, name) == 0;
}

/*
 * find_aggregate - find or create the aggregate bucket for one syscall
 *
 * Returns: The aggregate bucket, or NULL when the table is full.
 */
static struct alert_aggregate *find_aggregate(
		struct audit_alert_engine *engine, int syscall,
		const char *name)
{
	size_t index = syscall_hash(syscall, name) &
		       (ALERT_AGGREGATE_SIZE - 1);
	size_t probe;

	for (probe = 0; probe < ALERT_AGGREGATE_SIZE; probe++) {
		struct alert_aggregate *aggregate =
			&engine->aggregates[index];

		if (!aggregate->used) {
			aggregate->used = 1;
			aggregate->syscall = syscall;
			if (name != NULL)
				snprintf(aggregate->syscall_name,
					 sizeof(aggregate->syscall_name),
					 "%s", name);
			return aggregate;
		}

		if (same_syscall(aggregate, syscall, name))
			return aggregate;

		index = (index + 1) & (ALERT_AGGREGATE_SIZE - 1);
	}

	return NULL;
}

/*
 * rule_matches - test whether a rule selects a parsed syscall record
 *
 * Returns: Non-zero when the rule matches.
 */
static int rule_matches(const struct alert_rule *rule, int syscall,
			const char *syscall_name, const char *key)
{
	if (rule->config.syscall >= 0 && rule->config.syscall != syscall)
		return 0;

	if (rule->config.syscall_name != NULL &&
	    rule->config.syscall_name[0] != '\0') {
		if (syscall_name[0] == '\0' ||
		    strcmp(rule->config.syscall_name, syscall_name) != 0)
			return 0;
	}

	if (rule->config.key != NULL && rule->config.key[0] != '\0' &&
	    strcmp(rule->config.key, "*") != 0) {
		if (key[0] == '\0' || strcmp(rule->config.key, key) != 0)
			return 0;
	}

	return 1;
}

/*
 * record_latency - update engine latency statistics for one processed record
 * @engine: engine receiving the measurement
 * @started: monotonic timestamp taken before processing
 *
 * Returns: Nothing.
 */
static void record_latency(struct audit_alert_engine *engine, uint64_t started)
{
	uint64_t elapsed;
	uint64_t finished = monotonic_ns();

	if (started == 0 || finished < started)
		return;

	elapsed = finished - started;
	engine->last_latency_ns = elapsed;
	engine->total_latency_ns += elapsed;
	if (elapsed > engine->max_latency_ns)
		engine->max_latency_ns = elapsed;
}

struct audit_alert_engine *audit_alert_engine_new(
		audit_alert_notify_fn notify, void *user_data)
{
	struct audit_alert_engine *engine;

	engine = calloc(1, sizeof(*engine));
	if (engine == NULL)
		return NULL;

	engine->notify = notify;
	engine->user_data = user_data;
	return engine;
}

void audit_alert_engine_free(struct audit_alert_engine *engine)
{
	free(engine);
}

int audit_alert_engine_add_rule(struct audit_alert_engine *engine,
		const struct audit_alert_rule_config *rule)
{
	struct alert_rule *stored;
	size_t index;

	if (engine == NULL || rule == NULL)
		return -EINVAL;
	if (engine->rule_count >= AUDIT_ALERT_MAX_RULES)
		return -ENOSPC;

	index = engine->rule_count;
	stored = &engine->rules[index];
	memset(stored, 0, sizeof(*stored));
	stored->used = 1;
	stored->config = *rule;

	if (rule->syscall_name != NULL)
		snprintf(stored->syscall_name, sizeof(stored->syscall_name),
			 "%s", rule->syscall_name);
	if (rule->key != NULL)
		snprintf(stored->key, sizeof(stored->key), "%s", rule->key);

	stored->config.syscall_name = stored->syscall_name[0] ?
		stored->syscall_name : NULL;
	stored->config.key = stored->key[0] ? stored->key : NULL;
	if (stored->config.threshold == 0)
		stored->config.threshold = 1;
	if (stored->config.id == 0)
		stored->config.id = (int)index + 1;

	engine->rule_count++;
	return (int)index;
}

size_t audit_alert_engine_rule_count(const struct audit_alert_engine *engine)
{
	return engine ? engine->rule_count : 0;
}

/*
 * record_is_syscall - check an explicit or embedded audit record type
 *
 * Returns: 1 for a syscall record, 0 for another record, negative on error.
 */
static int record_is_syscall(int record_type, const char *record,
			     size_t length)
{
	char type[AUDIT_ALERT_NAME_LEN];
	int type_number;
	int rc;

	if (record_type == AUDIT_ALERT_SYSCALL_RECORD)
		return 1;
	if (record_type > 0)
		return 0;

	rc = read_field(record, length, "type", type, sizeof(type));
	if (rc == -ENOENT)
		return 1; /* Raw SYSCALL payload supplied without its type. */
	if (rc < 0)
		return rc;

	if (parse_int(type, &type_number) == 0)
		return type_number == AUDIT_ALERT_SYSCALL_RECORD;

	return strcasecmp(type, "SYSCALL") == 0;
}

int audit_alert_engine_process(struct audit_alert_engine *engine,
		int record_type, const char *record, size_t length)
{
	char syscall_text[AUDIT_ALERT_NAME_LEN];
	char syscall_name[AUDIT_ALERT_NAME_LEN];
	char key[AUDIT_ALERT_KEY_LEN];
	bool matched[AUDIT_ALERT_MAX_RULES];
	struct alert_aggregate *aggregate;
	uint64_t started;
	size_t match_count = 0;
	int syscall = -1;
	size_t i;
	int rc = 0;
	int ret = 0;

	if (engine == NULL || record == NULL)
		return -EINVAL;
	if (length == 0)
		length = strnlen(record, ALERT_RECORD_LIMIT);
	if (length == 0)
		return -EINVAL;

	started = monotonic_ns();

	rc = record_is_syscall(record_type, record, length);
	if (rc <= 0) {
		ret = rc < 0 ? rc : 0;
		goto out;
	}

	rc = read_field(record, length, "syscall", syscall_text,
			sizeof(syscall_text));
	if (rc == -ENOENT) {
		ret = 0;
		goto out;
	}
	if (rc < 0) {
		ret = rc;
		goto out;
	}

	syscall_name[0] = '\0';
	if (parse_int(syscall_text, &syscall) != 0) {
		syscall = -1;
		snprintf(syscall_name, sizeof(syscall_name), "%s",
			 syscall_text);
	} else {
		snprintf(syscall_name, sizeof(syscall_name), "%d", syscall);
	}

	key[0] = '\0';
	(void)read_field(record, length, "key", key, sizeof(key));

	memset(matched, 0, sizeof(matched));
	if (engine->rule_count == 0) {
		match_count = 1; /* Implicit any-syscall rule. */
	} else {
		for (i = 0; i < engine->rule_count; i++) {
			if (rule_matches(&engine->rules[i], syscall,
					 syscall_name, key)) {
				matched[i] = true;
				match_count++;
			}
		}
	}

	if (match_count == 0)
		goto out;

	aggregate = find_aggregate(engine, syscall, syscall_name);
	if (aggregate == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	aggregate->count++;
	engine->total_count++;

	if (engine->rule_count == 0) {
		struct audit_alert_notification notification;

		memset(&notification, 0, sizeof(notification));
		notification.rule_index = 0;
		notification.rule_id = 0;
		notification.syscall = syscall;
		snprintf(notification.syscall_name,
			 sizeof(notification.syscall_name), "%s",
			 syscall_name);
		snprintf(notification.key, sizeof(notification.key), "%s",
			 key);
		notification.count = aggregate->count;
		notification.threshold = 1;
		if (started)
			notification.processing_ns = monotonic_ns() - started;

		engine->notification_count++;
		if (engine->notify != NULL)
			engine->notify(&notification, engine->user_data);
	} else {
		for (i = 0; i < engine->rule_count; i++) {
			struct audit_alert_notification notification;
			struct alert_rule *rule;

			if (!matched[i])
				continue;

			rule = &engine->rules[i];
			if (rule->config.threshold > 1 &&
			    aggregate->count % rule->config.threshold != 0)
				continue;

			memset(&notification, 0, sizeof(notification));
			notification.rule_index = i;
			notification.rule_id = rule->config.id;
			notification.syscall = syscall;
			snprintf(notification.syscall_name,
				 sizeof(notification.syscall_name), "%s",
				 syscall_name);
			snprintf(notification.key,
				 sizeof(notification.key), "%s", key);
			notification.count = aggregate->count;
			notification.threshold = rule->config.threshold;
			if (started)
				notification.processing_ns =
					monotonic_ns() - started;

			engine->notification_count++;
			if (engine->notify != NULL)
				engine->notify(&notification,
					       engine->user_data);
		}
	}

out:
	record_latency(engine, started);
	return ret;
}

int audit_alert_engine_process_line(struct audit_alert_engine *engine,
		const char *line)
{
	if (line == NULL)
		return -EINVAL;

	return audit_alert_engine_process(engine, 0, line, strlen(line));
}

uint64_t audit_alert_engine_syscall_count(
		const struct audit_alert_engine *engine, int syscall)
{
	size_t index;
	size_t probe;

	if (engine == NULL || syscall < 0)
		return 0;

	index = syscall_hash(syscall, NULL) & (ALERT_AGGREGATE_SIZE - 1);
	for (probe = 0; probe < ALERT_AGGREGATE_SIZE; probe++) {
		const struct alert_aggregate *aggregate =
			&engine->aggregates[index];

		if (!aggregate->used)
			return 0;
		if (aggregate->syscall == syscall)
			return aggregate->count;

		index = (index + 1) & (ALERT_AGGREGATE_SIZE - 1);
	}

	return 0;
}

uint64_t audit_alert_engine_name_count(
		const struct audit_alert_engine *engine, const char *name)
{
	size_t i;

	if (engine == NULL || name == NULL || name[0] == '\0')
		return 0;

	for (i = 0; i < ALERT_AGGREGATE_SIZE; i++) {
		const struct alert_aggregate *aggregate =
			&engine->aggregates[i];

		if (aggregate->used && aggregate->syscall < 0 &&
		    strcmp(aggregate->syscall_name, name) == 0)
			return aggregate->count;
	}

	return 0;
}

uint64_t audit_alert_engine_total_count(
		const struct audit_alert_engine *engine)
{
	return engine ? engine->total_count : 0;
}

uint64_t audit_alert_engine_notification_count(
		const struct audit_alert_engine *engine)
{
	return engine ? engine->notification_count : 0;
}

uint64_t audit_alert_engine_last_latency_ns(
		const struct audit_alert_engine *engine)
{
	return engine ? engine->last_latency_ns : 0;
}

uint64_t audit_alert_engine_max_latency_ns(
		const struct audit_alert_engine *engine)
{
	return engine ? engine->max_latency_ns : 0;
}

uint64_t audit_alert_engine_total_latency_ns(
		const struct audit_alert_engine *engine)
{
	return engine ? engine->total_latency_ns : 0;
}

int audit_alert_latency_within_budget(uint64_t latency_ns)
{
	return latency_ns <= AUDIT_ALERT_LATENCY_BUDGET_NS;
}
