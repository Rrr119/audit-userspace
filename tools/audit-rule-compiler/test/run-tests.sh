#!/bin/sh

set -u

: "${COMPILER:?COMPILER is not set}"
: "${srcdir:?srcdir is not set}"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/audit-rule-compiler.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT QUIT TERM

fail()
{
	echo "FAIL: $*" >&2
	exit 1
}

examples=$(grep -c '^# [0-9][0-9]:' \
	"$srcdir/examples/conflicts.rules")
[ "$examples" -eq 20 ] || fail "expected 20 conflict examples, got $examples"

if "$COMPILER" --check "$srcdir/examples/conflicts.rules" \
	>"$tmpdir/conflicts.out" 2>"$tmpdir/conflicts.err"; then
	fail "conflict fixture unexpectedly passed"
fi
[ ! -s "$tmpdir/conflicts.out" ] ||
	fail "check mode wrote rules to stdout"
conflicts=$(grep -c 'error: conflict' "$tmpdir/conflicts.err")
[ "$conflicts" -ge 20 ] ||
	fail "expected at least 20 conflict diagnostics, got $conflicts"

if "$COMPILER" --check "$srcdir/examples/duplicates.rules" \
	>"$tmpdir/duplicates.out" 2>"$tmpdir/duplicates.err"; then
	fail "duplicate fixture unexpectedly passed"
fi
grep -q 'error: duplicate rule' "$tmpdir/duplicates.err" ||
	fail "duplicate rule was not diagnosed"

cat >"$tmpdir/duplicate-fields.rules" <<'EOF'
-a always,exit -F arch=b64 -S open,open -F uid=0 -F uid=0 -k access -k access
EOF
"$COMPILER" "$tmpdir/duplicate-fields.rules" \
	>"$tmpdir/duplicate-fields.out" 2>"$tmpdir/duplicate-fields.err" ||
	fail "redundant field fixture failed to compile"
grep -q 'warning: duplicate field' "$tmpdir/duplicate-fields.err" ||
	fail "duplicate field was not diagnosed"
grep -q 'warning: duplicate key' "$tmpdir/duplicate-fields.err" ||
	fail "duplicate key was not diagnosed"
printf '%s\n' \
	'-a always,exit -F arch=b64 -F uid=0 -S open -k access' \
	>"$tmpdir/duplicate-fields.expected"
diff -u "$tmpdir/duplicate-fields.expected" \
	"$tmpdir/duplicate-fields.out" ||
	fail "duplicate field normalization is incorrect"
if "$COMPILER" --strict "$tmpdir/duplicate-fields.rules" \
	>"$tmpdir/duplicate-fields-strict.out" \
	2>"$tmpdir/duplicate-fields-strict.err"; then
	fail "strict mode accepted duplicate fields"
fi

"$COMPILER" "$srcdir/examples/minimize.rules" \
	>"$tmpdir/minimize.out" 2>"$tmpdir/minimize.err" ||
	fail "minimize fixture failed to compile"
diff -u "$srcdir/examples/minimize.expected" "$tmpdir/minimize.out" ||
	fail "minimized rules differ from expected output"

"$COMPILER" "$tmpdir/minimize.out" \
	>"$tmpdir/idempotent.out" 2>"$tmpdir/idempotent.err" ||
	fail "minimized output did not recompile"
diff -u "$tmpdir/minimize.out" "$tmpdir/idempotent.out" ||
	fail "normalized output is not idempotent"

"$COMPILER" --check "$srcdir/examples/clean.rules" \
	>"$tmpdir/clean.out" 2>"$tmpdir/clean.err" ||
	fail "clean fixture failed validation"

exit 0
