/*
 * test-alert-plugin.c - plugin configuration and entry-point tests
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
#include <unistd.h>

#define main audisp_alert_main
#include "audisp-alert.c"
#undef main

static struct audit_alert_notification captured;
static int captured_count;

/*
 * capture_note - retain the plugin engine's notification
 *
 * Returns: None.
 */
static void capture_note(const struct audit_alert_notification *note,
			 void *user_data)
{
	(void)user_data;
	captured = *note;
	captured_count++;
}

static void test_load_ten_rules_and_match(void)
{
	char path[] = "/tmp/audisp-alert-rules-XXXXXX";
	struct audit_alert_engine *engine;
	char record[512];
	int fd;
	int i;

	fd = mkstemp(path);
	assert(fd >= 0);

	FILE *rules = fdopen(fd, "w");
	assert(rules != NULL);
	fputs("# Ten test rules\n", rules);
	for (i = 0; i < 10; i++)
		fprintf(rules, "%d rule-%d 1\n", 400 + i, i);
	assert(fclose(rules) == 0);

	engine = audit_alert_engine_new(capture_note, NULL);
	assert(engine != NULL);
	assert(alert_load_rules(engine, path) == 0);
	unlink(path);

	assert(audit_alert_engine_rule_count(engine) == 10);
	snprintf(record, sizeof(record),
		 "type=SYSCALL msg=audit(1:1): syscall=409 key=\"rule-9\"");
	assert(audit_alert_engine_process_line(engine, record) == 0);
	assert(captured_count == 1);
	assert(captured.rule_id == 10);
	assert(captured.syscall == 409);
	assert(strcmp(captured.key, "rule-9") == 0);
	assert(captured.count == 1);

	audit_alert_engine_free(engine);
}

static void test_handle_line_entry_point(void)
{
	alert_engine = audit_alert_engine_new(NULL, NULL);
	assert(alert_engine != NULL);

	assert(audisp_alert_handle_line(
		"type=SYSCALL syscall=59 key=\"entry\"") == 0);
	assert(audit_alert_engine_syscall_count(alert_engine, 59) == 1);

	audit_alert_engine_free(alert_engine);
	alert_engine = NULL;
}

int main(void)
{
	test_load_ten_rules_and_match();
	test_handle_line_entry_point();
	return 0;
}
