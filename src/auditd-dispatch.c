/* auditd-dispatch.c -- 
 * Copyright 2005-07,2013,2016-17 Red Hat Inc., Durham, North Carolina.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Junji Kanemaru <junji.kanemaru@linuon.com>
 */

#include "config.h"
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "libaudit.h"
#include "private.h"
#include "auditd-dispatch.h"
#include "auditd-alert.h"
#include "libdisp.h"


static struct audit_alert_engine *dispatch_alert_engine;

/*
 * auditd_dispatch_set_alert_engine - attach a non-owning alert engine
 * @engine: engine to inspect valid outgoing records, or NULL to detach
 *
 * The engine is called before dispatcher queueing so plugin backpressure or
 * drops do not suppress rule alerts. Dispatch return codes and queue ownership
 * remain unchanged.
 *
 * Returns: None.
 */
void auditd_dispatch_set_alert_engine(struct audit_alert_engine *engine)
{
	dispatch_alert_engine = engine;
}

/* This function returns 1 on error & 0 on success */
int init_dispatcher(const struct daemon_conf *config)
{
	return libdisp_init(config);
}

void shutdown_dispatcher(void)
{
	libdisp_shutdown();
}

void reconfigure_dispatcher(const struct daemon_conf *config)
{
	libdisp_reconfigure(config);
}

/*
 * Returns 0 on success,
 * 1 if the event could not be queued due to overflow or
 * when processing is suspended, and
 * -1 on other errors
 */
int dispatch_event(const struct audit_reply *rep, int protocol_ver)
{
	event_t *e;
	const char *alert_payload = NULL;
	size_t alert_length = 0;
	int rc;

	if (!libdisp_active())
		return 0;

	// Translate event into dispatcher format
	e = malloc(sizeof(event_t));
	if (e == NULL) {
		increment_plugin_dropped();
		return -1;
	}

	e->hdr.ver = protocol_ver;
	e->hdr.hlen = sizeof(struct audit_dispatcher_header);
	e->hdr.type = rep->type;

	if (protocol_ver == AUDISP_PROTOCOL_VER) {
		/* The kernel audit subsystem sets nlmsg_len to the payload
		 * size only (skb->len - NLMSG_HDRLEN), not the total
		 * message length. */
		if (rep->msg.nlh.nlmsg_len > sizeof(e->data)) {
			free(e);
			increment_plugin_dropped();
			return -1;
		}
		e->hdr.size = rep->msg.nlh.nlmsg_len;
		memcpy(e->data, (void*)rep->msg.data, e->hdr.size);
		alert_payload = (const char *)rep->msg.data;
		alert_length = e->hdr.size;
	} else if (protocol_ver == AUDISP_PROTOCOL_VER2) {
		e->hdr.size = rep->len;
		memcpy(e->data, (void*)rep->message, e->hdr.size);
		alert_payload = rep->message;
		alert_length = e->hdr.size;
	} else {
		free(e);
		increment_plugin_dropped();
		return 0;
	}

	if (dispatch_alert_engine != NULL && alert_payload != NULL)
		(void)audit_alert_engine_process(dispatch_alert_engine,
						 rep->type, alert_payload,
						 alert_length);

	rc = libdisp_enqueue(e);
	if (rc < 0)
		increment_plugin_dropped();
	return rc;
}
