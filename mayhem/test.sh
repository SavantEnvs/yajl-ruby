#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's rspec suite (spec/), run by tmp/mayhem/yajl_ruby: a ruby interpreter with the yajl
# extension from ext/yajl (built by build.sh with normal flags) linked in, so `require 'yajl'` loads
# this tree's lib/ + C code. Specs that need gems absent from the image (activesupport) are excluded.
RUNNER="$SRC/tmp/mayhem/yajl_ruby"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing — run mayhem/build.sh first" >&2
  emit_ctrf "rspec" 0 1 0
  exit 1
fi
SPECS=$(find spec -name '*_spec.rb' ! -name active_support_spec.rb | sort)
LOG="$(mktemp)"
# Child `ruby` processes spawned by the specs use the same interpreter and this tree's lib/.
export PATH="$SRC/tmp/mayhem/bin:$PATH" RUBYLIB="$SRC/lib${RUBYLIB:+:$RUBYLIB}"
"$RUNNER" -I"$SRC/lib" -I"$SRC/spec" -e 'require "rspec/core"; exit RSpec::Core::Runner.run(ARGV)' -- \
  --format progress $SPECS 2>&1 | tee "$LOG"
summary="$(grep -E '^[0-9]+ examples?, [0-9]+ failures?' "$LOG" | tail -1)"
rm -f "$LOG"
if [ -z "$summary" ]; then
  echo "no rspec summary line — the suite did not run" >&2
  emit_ctrf "rspec" 0 1 0
  exit 1
fi
total=$(sed -E 's/^([0-9]+) examples?.*/\1/' <<<"$summary")
failed=$(sed -E 's/.* ([0-9]+) failures?.*/\1/' <<<"$summary")
pending=$(grep -oE '[0-9]+ pending' <<<"$summary" | cut -d' ' -f1 || true); pending=${pending:-0}

# GC.stress pass: the fuzz targets keep ruby's GC off between collections (see ruby_parser_fuzzer.c),
# so a GC-marking bug in yajl_ext.c (an unmarked VALUE held by a parser/projector) is invisible to them.
# Re-run the Projector specs (spec/projection/projection.rb, not matched by *_spec.rb above) and the
# one-off parser specs with a GC on every allocation. Only these: the whole suite takes >15 min stressed.
LOG="$(mktemp)"
"$RUNNER" -I"$SRC/lib" -I"$SRC/spec" -e 'require "rspec/core"
RSpec.configure { |c| c.around(:each) { |e| begin; GC.stress = true; e.run; ensure; GC.stress = false; end } }
exit RSpec::Core::Runner.run(ARGV)' -- --format progress spec/projection/projection.rb spec/parsing/one_off_spec.rb 2>&1 | tee "$LOG"
gsummary="$(grep -E '^[0-9]+ examples?, [0-9]+ failures?' "$LOG" | tail -1)"
rm -f "$LOG"
if [ -z "$gsummary" ]; then
  echo "no rspec summary line for the GC.stress pass — it did not run" >&2
  gsummary="1 example, 1 failure"
fi
total=$(( total + $(sed -E 's/^([0-9]+) examples?.*/\1/' <<<"$gsummary") ))
failed=$(( failed + $(sed -E 's/.* ([0-9]+) failures?.*/\1/' <<<"$gsummary") ))
gpending=$(grep -oE '[0-9]+ pending' <<<"$gsummary" | cut -d' ' -f1 || true); pending=$(( pending + ${gpending:-0} ))
emit_ctrf "rspec" $(( total - failed - pending )) "$failed" "$pending"
