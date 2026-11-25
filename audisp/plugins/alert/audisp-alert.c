/* audisp-alert.c -- real-time rule alerts aggregated by syscall
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif

#include "auplugin.h"
#include "auditd-alert.h"
#include "libaudit.h"

static volatile sig_atomic_t stop;
static volatile sig_atomic_t hup;
static struct audit_alert_engine *alert_engine;
static char *alert_rules_file;
static int alert_priority = LOG_ALERT;
static int alert_facility = LOG_USER;

static const struct log_name {
	const char *name;
	int value;
} log_names[] = {
	{ "LOG_EMERG", LOG_EMERG },
	{ "LOG_ALERT", LOG_ALERT },
	{ "LOG_CRIT", LOG_CRIT },
	{ "LOG_ERR", LOG_ERR },
	{ "LOG_WARNING", LOG_WARNING },
	{ "LOG_NOTICE", LOG_NOTICE },
	{ "LOG_INFO", LOG_INFO },
	{ "LOG_DEBUG", LOG_DEBUG },
	{ "LOG_KERN", LOG_KERN },
	{ "LOG_USER", LOG_USER },
	{ "LOG_MAIL", LOG_MAIL },
	{ "LOG_DAEMON", LOG_DAEMON },
	{ "LOG_AUTH", LOG_AUTH },
	{ "LOG_SYSLOG", LOG_SYSLOG },
	{ "LOG_LPR", LOG_LPR },
	{ "LOG_NEWS", LOG_NEWS },
	{ "LOG_UUCP", LOG_UUCP },
	{ "LOG_CRON", LOG_CRON },
	{ "LOG_AUTHPRIV", LOG_AUTHPRIV },
	{ "LOG_LOCAL0", LOG_LOCAL0 },
	{ "LOG_LOCAL1", LOG_LOCAL1 },
	{ "LOG_LOCAL2", LOG_LOCAL2 },
	{ "LOG_LOCAL3", LOG_LOCAL3 },
	{ "LOG_LOCAL4", LOG_LOCAL4 },
	{ "LOG_LOCAL5", LOG_LOCAL5 },
	{ "LOG_LOCAL6", LOG_LOCAL6 },
	{ "LOG_LOCAL7", LOG_LOCAL7 },
};

/*
 * term_handler - ask the plugin event loop to exit
 * @sig: signal number
 * @info: signal sender information
 * @context: unused signal context
 *
 * Only the parent dispatcher may stop the plugin.
 */
static void term_handler(int sig, siginfo_t *info, void *context)
{
	(void)sig;
	(void)context;

	if (info != NULL && info->si_pid != getppid())
		return;
	stop = 1;
}

/*
 * hup_handler - flag that rule configuration should be reloaded
 * @sig: signal number
 *
 * Returns: None.
 */
static void hup_handler(int sig)
{
	(void)sig;
	hup = 1;
}

/*
 * lookup_log_name - translate a LOG_* argument to its numeric value
 * @text: configuration token
 * @value: receives the syslog constant
 *
 * Returns: 0 when recognized and -EINVAL otherwise.
 */
static int lookup_log_name(const char *text, int *value)
{
	size_t i;

	for (i = 0; i < sizeof(log_names) / sizeof(log_names[0]); i++) {
		if (strcmp(text, log_names[i].name) == 0) {
			*value = log_names[i].value;
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * alert_notify_syslog - emit one real-time aggregated alert
 * @notification: alert count and identity
 * @user_data: unused callback context
 *
 * Returns: None.
 */
static void alert_notify_syslog(
		const struct audit_alert_notification *notification,
		void *user_data)
{
	(void)user_data;

	syslog(alert_priority,
	       "audit-rule-alert rule_id=%d rule_index=%zu syscall=%d "
	       "syscall_name=%s key=%s count=%llu threshold=%u "
	       "processing_ns=%llu",
	       notification->rule_id, notification->rule_index,
	       notification->syscall, notification->syscall_name,
	       notification->key[0] ? notification->key : "-",
	       (unsigned long long)notification->count,
	       notification->threshold,
	       (unsigned long long)notification->processing_ns);
}

/*
 * parse_syscall_token - parse a numeric or named syscall selector
 * @token: rule file token
 * @config: rule configuration to update
 * @name_storage: storage for a named selector
 * @name_size: size of @name_storage
 *
 * Returns: 0 on success and -EINVAL on an invalid number.
 */
static int parse_syscall_token(const char *token,
			       struct audit_alert_rule_config *config,
			       char *name_storage, size_t name_size)
{
	char *end;
	long number;

	if (strcmp(token, "*") == 0 || strcmp(token, "-") == 0) {
		config->syscall = -1;
		return 0;
	}

	errno = 0;
	number = strtol(token, &end, 10);
	if (errno == 0 && end != token && *end == '\0') {
		config->syscall = (int)number;
		return 0;
	}

	snprintf(name_storage, name_size, "%s", token);
	config->syscall = -1;
	config->syscall_name = name_storage;
	return 0;
}

/*
 * alert_load_rules - load syscall/key/threshold rules from a simple file
 * @engine: engine receiving the rules
 * @path: rule file path
 *
 * Blank lines and # comments are ignored. Non-comment lines contain
 * "syscall [key] [threshold]", with "*" or "-" selecting any value.
 *
 * Returns: 0 on success and -1 when the file cannot be read or a rule is bad.
 */
static int alert_load_rules(struct audit_alert_engine *engine, const char *path)
{
	char line[4096];
	FILE *file;
	int line_number = 0;

	if (path == NULL)
		return 0;

	file = fopen(path, "r");
	if (file == NULL) {
		syslog(LOG_ERR, "audisp-alert cannot open rules %s: %m", path);
		return -1;
	}

	while (fgets(line, sizeof(line), file) != NULL) {
		struct audit_alert_rule_config config;
		char syscall_name[AUDIT_ALERT_NAME_LEN];
		char *saveptr = NULL;
		char *token;
		char *syscall_token;
		char *key_token = NULL;
		char *threshold_token = NULL;
		char *comment;

		line_number++;
		comment = strchr(line, '#');
		if (comment != NULL)
			*comment = '\0';

		syscall_token = strtok_r(line, " \t\r\n", &saveptr);
		if (syscall_token == NULL)
			continue;

		key_token = strtok_r(NULL, " \t\r\n", &saveptr);
		threshold_token = strtok_r(NULL, " \t\r\n", &saveptr);
		token = strtok_r(NULL, " \t\r\n", &saveptr);
		if (token != NULL) {
			syslog(LOG_ERR,
			       "audisp-alert rule %d has too many fields",
			       line_number);
			fclose(file);
			return -1;
		}

		memset(&config, 0, sizeof(config));
		syscall_name[0] = '\0';
		config.syscall = -1;
		config.threshold = 1;

		if (parse_syscall_token(syscall_token, &config, syscall_name,
					sizeof(syscall_name)) != 0) {
			fclose(file);
			return -1;
		}

		if (key_token != NULL && strcmp(key_token, "-") != 0 &&
		    strcmp(key_token, "*") != 0)
			config.key = key_token;

		if (threshold_token != NULL) {
			char *end;
			long threshold;

			errno = 0;
			threshold = strtol(threshold_token, &end, 10);
			if (errno != 0 || end == threshold_token ||
			    *end != '\0' || threshold <= 0) {
				syslog(LOG_ERR,
				       "audisp-alert rule %d has bad threshold",
				       line_number);
				fclose(file);
				return -1;
			}
			config.threshold = (unsigned int)threshold;
		}

		if (audit_alert_engine_add_rule(engine, &config) < 0) {
			syslog(LOG_ERR,
			       "audisp-alert cannot add rule %d", line_number);
			fclose(file);
			return -1;
		}
	}

	fclose(file);
	return 0;
}

/*
 * alert_reload - atomically replace the engine after SIGHUP
 *
 * Returns: 0 on success and -1 if the new engine or rules cannot be created.
 */
static int alert_reload(void)
{
	struct audit_alert_engine *replacement;

	replacement = audit_alert_engine_new(alert_notify_syslog, NULL);
	if (replacement == NULL) {
		syslog(LOG_ERR, "audisp-alert cannot allocate alert engine");
		return -1;
	}

	if (alert_load_rules(replacement, alert_rules_file) != 0) {
		audit_alert_engine_free(replacement);
		return -1;
	}

	if (alert_engine != NULL)
		audit_alert_engine_free(alert_engine);
	alert_engine = replacement;
	hup = 0;
	return 0;
}

/*
 * audisp_alert_handle_line - process one dispatcher string record
 * @line: NUL terminated record line
 *
 * Returns: Zero on success or a negative errno value.
 */
int audisp_alert_handle_line(const char *line)
{
	if (alert_engine == NULL)
		return -EAGAIN;
	return audit_alert_engine_process_line(alert_engine, line);
}

/*
 * init_alert - parse plugin arguments and load configured rules
 * @argc: argument count
 * @argv: argument vector
 *
 * Returns: 0 on success and 1 when configuration is invalid.
 */
static int init_alert(int argc, const char *argv[])
{
	int i;

	for (i = 1; i < argc; i++) {
		const char *argument = argv[i];
		int value;

		if (argument == NULL)
			continue;

		if (strncmp(argument, "rules=", 6) == 0) {
			free(alert_rules_file);
			alert_rules_file = strdup(argument + 6);
			if (alert_rules_file == NULL)
				return 1;
		} else if (strncmp(argument, "rule-file=", 10) == 0) {
			free(alert_rules_file);
			alert_rules_file = strdup(argument + 10);
			if (alert_rules_file == NULL)
				return 1;
		} else if (lookup_log_name(argument, &value) == 0) {
			if (strncmp(argument, "LOG_LOCAL", 9) == 0 ||
			    value == LOG_AUTH || value == LOG_AUTHPRIV ||
			    value == LOG_DAEMON || value == LOG_SYSLOG ||
			    value == LOG_USER || value == LOG_MAIL ||
			    value == LOG_KERN || value == LOG_CRON ||
			    value == LOG_LPR || value == LOG_NEWS ||
			    value == LOG_UUCP)
				alert_facility = value;
			else
				alert_priority = value;
		} else if (argument[0] == '/') {
			free(alert_rules_file);
			alert_rules_file = strdup(argument);
			if (alert_rules_file == NULL)
				return 1;
		} else {
			syslog(LOG_ERR, "audisp-alert unknown argument %s",
			       argument);
			return 1;
		}
	}

	openlog("audisp-alert", LOG_PID, alert_facility);
	if (alert_reload() != 0)
		return 1;

	syslog(LOG_INFO, "audisp-alert initialized with %zu rules",
	       audit_alert_engine_rule_count(alert_engine));
	return 0;
}

int main(int argc, const char *argv[])
{
	char record[MAX_AUDIT_MESSAGE_LENGTH + 1];
	struct sigaction action;

	openlog("audisp-alert", LOG_PID, alert_facility);
	if (init_alert(argc, argv))
		return 1;

	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = hup_handler;
	sigaction(SIGHUP, &action, NULL);

	action.sa_sigaction = term_handler;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &action, NULL);

#ifdef HAVE_LIBCAP_NG
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING,
		       "audisp-alert could not drop capabilities");
#endif

	do {
		fd_set read_mask;
		int ready;

		if (hup)
			alert_reload();

		FD_ZERO(&read_mask);
		FD_SET(STDIN_FILENO, &read_mask);
		do {
			ready = select(1, &read_mask, NULL, NULL, NULL);
		} while (ready < 0 && errno == EINTR && !stop && !hup);

		if (!stop && !hup && ready > 0 &&
		    FD_ISSET(STDIN_FILENO, &read_mask)) {
			do {
				int read_rc = auplugin_fgets(
					record, MAX_AUDIT_MESSAGE_LENGTH,
					STDIN_FILENO);

				if (read_rc < 0) {
					syslog(LOG_ERR,
					       "auplugin_fgets failed: %m");
					stop = 1;
					break;
				}
				if (read_rc > 0)
					(void)audisp_alert_handle_line(record);
			} while (auplugin_fgets_more(
					MAX_AUDIT_MESSAGE_LENGTH));
		}

		if (auplugin_fgets_eof())
			break;
	} while (!stop);

	audit_alert_engine_free(alert_engine);
	free(alert_rules_file);
	closelog();
	return 0;
}
