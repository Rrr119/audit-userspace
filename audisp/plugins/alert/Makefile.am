# Makefile.am for the syscall-aggregated alert plugin

CONFIG_CLEAN_FILES = *.rej *.orig
CONF_FILES = alert.conf
EXTRA_DIST = $(CONF_FILES)
man_MANS = audisp-alert.8

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/audisp \
	-I${top_srcdir}/common -I${top_srcdir}/auplugin \
	-I${top_srcdir}/auparse -I${top_srcdir}/src

prog_confdir = $(sysconfdir)/audit
plugin_confdir = $(prog_confdir)/plugins.d

sbin_PROGRAMS = audisp-alert
check_PROGRAMS = test-alert-plugin
TESTS = $(check_PROGRAMS)

audisp_alert_DEPENDENCIES = ${top_builddir}/lib/libaudit.la \
	${top_builddir}/auplugin/libauplugin.la
audisp_alert_SOURCES = audisp-alert.c alert_engine.c
audisp_alert_CFLAGS = -fPIE -DPIE -g -D_GNU_SOURCE -Wundef ${WFLAGS}
audisp_alert_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
audisp_alert_LDADD = $(CAPNG_LDADD) \
	${top_builddir}/lib/libaudit.la \
	${top_builddir}/auplugin/libauplugin.la

test_alert_plugin_SOURCES = test-alert-plugin.c alert_engine.c
test_alert_plugin_CFLAGS = $(audisp_alert_CFLAGS)
test_alert_plugin_LDFLAGS = $(audisp_alert_LDFLAGS)
test_alert_plugin_LDADD = $(audisp_alert_LDADD)
if HAVE_ASAN
test_alert_plugin_CFLAGS += ${ASAN_FLAGS}
test_alert_plugin_LDFLAGS += ${ASAN_FLAGS}
endif

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/alert.conf \
		${DESTDIR}${plugin_confdir}/alert.conf

uninstall-hook:
	rm -f ${DESTDIR}${plugin_confdir}/alert.conf
