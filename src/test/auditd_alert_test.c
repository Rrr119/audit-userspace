/*
 * auditd_alert_test.c - rule alert aggregation and latency tests
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../auditd-alert.c"

#define CAPTURED_NOTES 64

static struct audit_alert_notification notes[CAPTURED_NOTES];
static size_t note_count;
static uint64_t perf_calls;

/*
 * capture_note - retain an alert for assertions
 *
 * Returns: None.
 */
static void capture_note(const struct audit_alert_notification *note,
			 void *user_data)
{
	(void)user_data;

	if (note_count < CAPTURED_NOTES)
		notes[note_count] = *note;
	note_count++;
}

/*
 * perf_note - count alerts in the latency test without copying data
 *
 * Returns: None.
 */
static void perf_note(const struct audit_alert_notification *note,
		      void *user_data)
{
	uint64_t *calls = user_data;

	(void)note;
	if (calls != NULL)
		(*calls)++;
	else
		perf_calls++;
}

/*
 * now_ns - read monotonic time for test-side latency measurements
 *
 * Returns: Current monotonic time in nanoseconds.
 */
static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void reset_notes(void)
{
	memset(notes, 0, sizeof(notes));
	note_count = 0;
}

static void test_immediate_alert_and_syscall_count(void)
{
	struct audit_alert_engine *engine;
	struct audit_alert_rule_config rule = {
		.id = 7,
		.syscall = 59,
		.key = "exec-watch",
		.threshold = 1,
	};
	const char *record =
		"type=SYSCALL msg=audit(1721000000.123:42): "
		"arch=c000003e syscall=59 success=yes exit=0 "
		"comm=\"bash\" key=\"exec-watch\"";
	int i;

	reset_notes();
	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);
	assert(audit_alert_engine_add_rule(engine, &rule) == 0);
	assert(audit_alert_engine_rule_count(engine) == 1);

	for (i = 0; i < 3; i++)
		assert(audit_alert_engine_process_line(engine, record) == 0);

	assert(note_count == 3);
	assert(notes[0].rule_id == 7);
	assert(notes[0].syscall == 59);
	assert(strcmp(notes[0].key, "exec-watch") == 0);
	assert(notes[0].count == 1);
	assert(notes[2].count == 3);
	assert(audit_alert_engine_syscall_count(engine, 59) == 3);
	assert(audit_alert_engine_total_count(engine) == 3);
	assert(audit_alert_engine_notification_count(engine) == 3);

	audit_alert_engine_free(engine);
}

static void test_syscalls_aggregate_separately(void)
{
	struct audit_alert_engine *engine;

	reset_notes();
	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);

	assert(audit_alert_engine_process_line(engine,
		"syscall=42 key=\"first\"") == 0);
	assert(audit_alert_engine_process_line(engine,
		"syscall=42 key=\"first\"") == 0);
	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL msg=audit(1:3): syscall=43") == 0);

	assert(note_count == 3);
	assert(audit_alert_engine_syscall_count(engine, 42) == 2);
	assert(audit_alert_engine_syscall_count(engine, 43) == 1);
	assert(audit_alert_engine_syscall_count(engine, -1) == 0);

	audit_alert_engine_free(engine);
}

static void test_key_type_and_name_filters(void)
{
	struct audit_alert_engine *engine;
	struct audit_alert_rule_config key_rule = {
		.syscall = -1,
		.key = "wanted",
	};
	struct audit_alert_rule_config name_rule = {
		.syscall = -1,
		.syscall_name = "openat",
	};

	reset_notes();
	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);
	assert(audit_alert_engine_add_rule(engine, &key_rule) == 0);
	assert(audit_alert_engine_add_rule(engine, &name_rule) == 1);

	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL syscall=257 key=\"other\"") == 0);
	assert(note_count == 0);

	assert(audit_alert_engine_process_line(engine,
		"type=USER msg=audit(1:1): syscall=257 key=\"wanted\"") == 0);
	assert(note_count == 0);

	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL comm=\"a key=\\\"decoy\\\"\" "
		"syscall=257 key=\"wanted\"") == 0);
	assert(note_count == 1);
	assert(notes[0].rule_index == 0);
	assert(strcmp(notes[0].key, "wanted") == 0);

	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL syscall=257 key=\"wanted\"") == 0);
	assert(note_count == 2);
	assert(notes[1].rule_index == 0);
	assert(notes[1].syscall == 257);

	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL syscall=openat key=\"unmatched-key\"") == 0);
	assert(note_count == 3);
	assert(notes[2].rule_index == 1);
	assert(notes[2].syscall == -1);
	assert(strcmp(notes[2].syscall_name, "openat") == 0);
	assert(audit_alert_engine_name_count(engine, "openat") == 1);

	audit_alert_engine_free(engine);
}

static void test_threshold_reduces_notifications(void)
{
	struct audit_alert_engine *engine;
	struct audit_alert_rule_config rule = {
		.id = 9,
		.syscall = 5,
		.threshold = 3,
	};
	int i;

	reset_notes();
	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);
	assert(audit_alert_engine_add_rule(engine, &rule) == 0);

	for (i = 0; i < 5; i++)
		assert(audit_alert_engine_process(engine,
			AUDIT_ALERT_SYSCALL_RECORD,
			"syscall=5 key=\"threshold\"", 0) == 0);

	assert(audit_alert_engine_syscall_count(engine, 5) == 5);
	assert(audit_alert_engine_notification_count(engine) == 1);
	assert(note_count == 1);
	assert(notes[0].count == 3);
	assert(notes[0].threshold == 3);

	audit_alert_engine_free(engine);
}

static void test_dispatcher_string_formats(void)
{
	struct audit_alert_engine *engine;
	struct audit_alert_rule_config rule = {
		.syscall = 59,
		.key = "exec-rule",
	};
	const char *protocol_v1 =
		"type=SYSCALL msg=audit(1721000001.001:100): "
		"arch=c000003e syscall=59 exe=\"/usr/bin/id\" "
		"key=\"exec-rule\"\n";
	const char *protocol_v2 =
		"type=SYSCALL msg=audit(1721000001.002:101): "
		"arch=x86_64 syscall=59 success=yes exe=\"/usr/bin/id\" "
		"key=exec-rule\n";

	reset_notes();
	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);
	assert(audit_alert_engine_add_rule(engine, &rule) == 0);

	assert(audit_alert_engine_process_line(engine, protocol_v1) == 0);
	assert(audit_alert_engine_process_line(engine, protocol_v2) == 0);
	assert(note_count == 2);
	assert(audit_alert_engine_syscall_count(engine, 59) == 2);

	audit_alert_engine_free(engine);
}

/*
 * test_ten_rule_latency - keep rule lookup and aggregation in budget
 *
 * Ten configured rules receive 1,000 records each. The test measures only
 * the engine call, not test string construction, and requires every call to
 * stay below the public latency budget.
 */
static void test_ten_rule_latency(void)
{
	struct audit_alert_engine *engine;
	uint64_t calls = 0;
	uint64_t max_latency = 0;
	uint64_t total_latency = 0;
	char record[1024];
	int round, rule_index;

	engine = audit_alert_engine_new(perf_note, &calls);
	assert(engine != NULL);

	for (rule_index = 0; rule_index < 10; rule_index++) {
		struct audit_alert_rule_config rule = {
			.id = rule_index + 1,
			.syscall = 400 + rule_index,
		};
		char key[32];

		snprintf(key, sizeof(key), "rule-%d", rule_index);
		rule.key = key;
		assert(audit_alert_engine_add_rule(engine, &rule) ==
		       rule_index);
	}

	for (round = 0; round < 1000; round++) {
		for (rule_index = 0; rule_index < 10; rule_index++) {
			uint64_t started, elapsed;
			int length;

			length = snprintf(record, sizeof(record),
				"type=SYSCALL msg=audit(172100%04d.%03d:%d): "
				"arch=c000003e syscall=%d success=yes "
				"key=\"rule-%d\"",
				round, rule_index,
				round * 10 + rule_index,
				400 + rule_index, rule_index);
			assert(length > 0 && (size_t)length < sizeof(record));

			started = now_ns();
			assert(audit_alert_engine_process_line(engine,
							       record) == 0);
			elapsed = now_ns() - started;

			total_latency += elapsed;
			if (elapsed > max_latency)
				max_latency = elapsed;
			if (!audit_alert_latency_within_budget(elapsed)) {
				fprintf(stderr,
					"alert latency %llu ns exceeds "
					"%llu ns at rule %d round %d\n",
					(unsigned long long)elapsed,
					(unsigned long long)
						AUDIT_ALERT_LATENCY_BUDGET_NS,
					rule_index, round);
				assert(0);
			}
		}
	}

	assert(calls == 10000);
	assert(audit_alert_engine_total_count(engine) == 10000);
	assert(audit_alert_engine_notification_count(engine) == 10000);
	for (rule_index = 0; rule_index < 10; rule_index++)
		assert(audit_alert_engine_syscall_count(engine,
			400 + rule_index) == 1000);

	assert(audit_alert_engine_process_line(engine,
		"type=SYSCALL syscall=999 key=\"no-match\"") == 0);
	assert(audit_alert_engine_total_count(engine) == 10000);
	assert(audit_alert_engine_notification_count(engine) == 10000);
	assert(audit_alert_latency_within_budget(
		audit_alert_engine_last_latency_ns(engine)));

	assert(audit_alert_latency_within_budget(
		audit_alert_engine_max_latency_ns(engine)));
	assert(total_latency / 10000 < AUDIT_ALERT_LATENCY_BUDGET_NS / 10);

	printf("10-rule latency: max=%llu avg=%llu budget=%llu ns\n",
	       (unsigned long long)max_latency,
	       (unsigned long long)(total_latency / 10000),
	       (unsigned long long)AUDIT_ALERT_LATENCY_BUDGET_NS);

	audit_alert_engine_free(engine);
}

int main(void)
{
	test_immediate_alert_and_syscall_count();
	test_syscalls_aggregate_separately();
	test_key_type_and_name_filters();
	test_threshold_reduces_notifications();
	test_dispatcher_string_formats();
	test_ten_rule_latency();
	return 0;
}
