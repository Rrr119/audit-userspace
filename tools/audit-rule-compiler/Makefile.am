# Makefile.am --
# Copyright 2026 Red Hat Inc.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
# Boston, MA 02110-1335, USA.

CONFIG_CLEAN_FILES = *.loT *.rej *.orig

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib
AM_CFLAGS = -D_GNU_SOURCE ${WFLAGS}

bin_PROGRAMS = audit-rule-compiler
check_PROGRAMS = audit-rule-compiler-test
TESTS = test/run-tests.sh
dist_check_SCRIPTS = test/run-tests.sh

man_MANS = audit-rule-compiler.8

audit_rule_compiler_SOURCES = audit-rule-compiler.c
audit_rule_compiler_LDADD = ${top_builddir}/lib/libaudit.la
audit_rule_compiler_DEPENDENCIES = ${top_builddir}/lib/libaudit.la

audit_rule_compiler_test_SOURCES = audit-rule-compiler.c
audit_rule_compiler_test_LDADD = ${top_builddir}/lib/libaudit.la
audit_rule_compiler_test_DEPENDENCIES = ${top_builddir}/lib/libaudit.la

TESTS_ENVIRONMENT = \
	COMPILER='$(top_builddir)/tools/audit-rule-compiler/audit-rule-compiler-test' \
	srcdir='$(srcdir)'

EXTRA_DIST = $(man_MANS) \
	examples/conflicts.rules \
	examples/duplicates.rules \
	examples/minimize.rules \
	examples/minimize.expected \
	examples/clean.rules \
	test/run-tests.sh

examplesdir = $(docdir)/audit-rule-compiler/examples
dist_examples_DATA = \
	examples/conflicts.rules \
	examples/duplicates.rules \
	examples/minimize.rules \
	examples/minimize.expected \
	examples/clean.rules
