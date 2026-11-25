/* auditd-alert.h -- rule triggered alert aggregation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef AUDITD_ALERT_H
#define AUDITD_ALERT_H

#include <stddef.h>
#include <stdint.h>

#define AUDIT_ALERT_SYSCALL_RECORD 1300
#define AUDIT_ALERT_MAX_RULES 64
#define AUDIT_ALERT_KEY_LEN 256
#define AUDIT_ALERT_NAME_LEN 64

/* Ten small rules must complete well below this wall-clock budget. */
#define AUDIT_ALERT_LATENCY_BUDGET_NS (100ULL * 1000ULL * 1000ULL)

struct audit_alert_rule_config {
	int id;
	int syscall;			/* -1 matches any syscall */
	const char *syscall_name;	/* optional name match */
	const char *key;		/* NULL or "*" matches any key */
	unsigned int threshold;		/* notifications per aggregate count */
};

struct audit_alert_notification {
	int rule_id;
	size_t rule_index;
	int syscall;
	char syscall_name[AUDIT_ALERT_NAME_LEN];
	char key[AUDIT_ALERT_KEY_LEN];
	uint64_t count;
	unsigned int threshold;
	uint64_t processing_ns;
};

typedef void (*audit_alert_notify_fn)(
	const struct audit_alert_notification *notification,
	void *user_data);

struct audit_alert_engine;

struct audit_alert_engine *audit_alert_engine_new(
	audit_alert_notify_fn notify, void *user_data);
void audit_alert_engine_free(struct audit_alert_engine *engine);

int audit_alert_engine_add_rule(struct audit_alert_engine *engine,
		const struct audit_alert_rule_config *rule);
size_t audit_alert_engine_rule_count(
		const struct audit_alert_engine *engine);

int audit_alert_engine_process(struct audit_alert_engine *engine,
		int record_type, const char *record, size_t length);
int audit_alert_engine_process_line(struct audit_alert_engine *engine,
		const char *line);

uint64_t audit_alert_engine_syscall_count(
		const struct audit_alert_engine *engine, int syscall);
uint64_t audit_alert_engine_name_count(
		const struct audit_alert_engine *engine, const char *name);
uint64_t audit_alert_engine_total_count(
		const struct audit_alert_engine *engine);
uint64_t audit_alert_engine_notification_count(
		const struct audit_alert_engine *engine);
uint64_t audit_alert_engine_last_latency_ns(
		const struct audit_alert_engine *engine);
uint64_t audit_alert_engine_max_latency_ns(
		const struct audit_alert_engine *engine);
uint64_t audit_alert_engine_total_latency_ns(
		const struct audit_alert_engine *engine);

int audit_alert_latency_within_budget(uint64_t latency_ns);

/* Short aliases for callers and tests that prefer the audit_alert_* names. */
typedef struct audit_alert_engine audit_alert_engine;
typedef struct audit_alert_rule_config audit_alert_rule_config;
typedef struct audit_alert_notification audit_alert_notification;

static inline audit_alert_engine *audit_alert_init(
		audit_alert_notify_fn notify, void *user_data)
{
	return audit_alert_engine_new(notify, user_data);
}

static inline void audit_alert_destroy(audit_alert_engine *engine)
{
	audit_alert_engine_free(engine);
}

static inline int audit_alert_add_rule(audit_alert_engine *engine,
		const audit_alert_rule_config *rule)
{
	return audit_alert_engine_add_rule(engine, rule);
}

static inline int audit_alert_process_event(audit_alert_engine *engine,
		int record_type, const char *record, size_t length)
{
	return audit_alert_engine_process(engine, record_type, record, length);
}

static inline uint64_t audit_alert_get_count(
		const audit_alert_engine *engine, int syscall)
{
	return audit_alert_engine_syscall_count(engine, syscall);
}

#endif
