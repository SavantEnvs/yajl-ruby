#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Everything this script writes goes under tmp/ (upstream's .gitignore has `tmp/*`), so
# `git clean -ffdX` removes it and a re-run rebuilds from scratch.
OUT="$SRC/tmp/mayhem"
mkdir -p "$OUT/test-obj"
Y="$SRC/ext/yajl"
CORE="yajl yajl_alloc yajl_buf yajl_lex yajl_parser yajl_encode yajl_gen yajl_version"

# Ruby headers/library for the yajl_ext.c (Ruby glue) builds.
RUBY_HDR="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["rubyhdrdir"]')"
RUBY_ARCHHDR="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["rubyarchhdrdir"]')"
RUBY_LIBDIR="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["libdir"]')"
RUBY_SO="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["RUBY_SO_NAME"]')"
RUBY_CFLAGS="-I$RUBY_HDR -I$RUBY_ARCHHDR"
RUBY_LIBS="-L$RUBY_LIBDIR -l$RUBY_SO -lm"
# The fuzz/standalone builds of the Ruby glue link the STATIC libruby the Dockerfile builds under
# /opt/toolchains/deps (see there: libruby.so's general-dynamic TLS code is undecodable for Mayhem's
# symbolic executor; linked statically, every TLS access becomes local-exec). Its headers must match it.
RUBY_DEP="$(ls -d /opt/toolchains/deps/ruby-* | tail -1)"
FUZZ_RUBY_CFLAGS="-I$RUBY_DEP/include/ruby-3.3.0 -I$RUBY_DEP/include/ruby-3.3.0/x86_64-linux"
FUZZ_RUBY_LIBS="-Wl,--wrap=rb_bug $RUBY_DEP/lib/libruby-static.a -lz -lrt -ldl -lcrypt -lm -lpthread"

# 1) The yajl library (ext/yajl) with $SANITIZER_FLAGS + DWARF 3, so the fuzzed code is instrumented,
#    compiled twice: with SanitizerCoverage for the libFuzzer binaries (fuzz-obj/) and without it for the
#    standalone reproducers (sa-obj/, which must also link when SANITIZER_FLAGS is empty).
# UBSan's `function` check is relaxed (only it): yajl_gen.c calls yajl_buf_append(yajl_buf, const void *,
# unsigned) through its yajl_print_t (void *, const char *, unsigned) pointer on EVERY emitted token, so
# the check fires on any generator use and would hide everything else. ASan and the rest of UBSan halt.
UBSAN_RELAX="-fno-sanitize=function"
build_objs() {  # <objdir> <extra cflags>
  local d="$1" cov="$2" f extra
  mkdir -p "$d"
  for f in $CORE yajl_ext; do
    extra=""; [ "$f" = yajl_ext ] && extra="$FUZZ_RUBY_CFLAGS"
    $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $cov -O1 -I"$Y" $extra -c "$Y/$f.c" -o "$d/$f.o"
  done
  for h in $HARNESSES; do
    extra=""; src="$h"
    case "$h" in
      ruby_parser_fuzzer) extra="$FUZZ_RUBY_CFLAGS" ;;
      # projector-fuzzer: the same harness source, Projector over the raw input (see its header).
      projector_fuzzer) extra="$FUZZ_RUBY_CFLAGS -DPROJECTOR_FUZZER"; src=ruby_parser_fuzzer ;;
    esac
    $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $cov -O1 -I"$Y" $extra -c "$SRC/mayhem/harnesses/$src.c" -o "$d/$h.o"
  done
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$d/lsan_off.o"
}
HARNESSES="json_fuzzer json_reformat_fuzzer json_gen_fuzzer ruby_parser_fuzzer projector_fuzzer"
build_objs "$OUT/fuzz-obj" "-fsanitize=fuzzer-no-link"
build_objs "$OUT/sa-obj" ""
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/sa-obj/standalone_main.o"

# 2) Each harness twice: libFuzzer binary + run-once standalone reproducer.
for h in $HARNESSES; do
  objs=""; for f in $CORE; do objs="$objs $f.o"; done
  libs=""
  case "$h" in ruby_parser_fuzzer|projector_fuzzer) objs="$objs yajl_ext.o"; libs="$FUZZ_RUBY_LIBS" ;; esac
  (cd "$OUT/fuzz-obj" && $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$h.o" $objs lsan_off.o $libs -o "$OUT/$h")
  (cd "$OUT/sa-obj" && $CXX $SANITIZER_FLAGS $DEBUG_FLAGS standalone_main.o "$h.o" $objs lsan_off.o $libs -o "$OUT/$h-standalone")
done

# 3) Test build with NORMAL flags: a ruby interpreter with the yajl extension linked in, which
#    mayhem/test.sh uses to run upstream's rspec suite (spec/).
for f in $CORE yajl_ext; do
  $CC -O2 -g $COVERAGE_FLAGS -fPIC -I"$Y" $RUBY_CFLAGS -c "$Y/$f.c" -o "$OUT/test-obj/$f.o"
done
$CC -O2 -g $COVERAGE_FLAGS $RUBY_CFLAGS -c "$SRC/mayhem/harnesses/yajl_ruby_main.c" -o "$OUT/test-obj/yajl_ruby_main.o"
$CC $COVERAGE_FLAGS "$OUT"/test-obj/*.o $RUBY_LIBS -o "$OUT/yajl_ruby"
# spec/parsing/large_number_spec.rb execs `ruby` from PATH: test.sh puts this one first.
mkdir -p "$OUT/bin" && ln -sf ../yajl_ruby "$OUT/bin/ruby"

echo "built: $(cd "$OUT" && ls -1 | grep -v obj | tr '\n' ' ')"
