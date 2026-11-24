/*
 * ruby_parser_fuzzer: the Ruby glue of yajl-ruby (ext/yajl/yajl_ext.c) inside an embedded ruby.
 * Per input: Yajl::Parser.new(opts).parse(json) (Ruby object-building callbacks, symbolize_keys,
 * chunked parse_chunk), Yajl::Encoder.encode of the result (pretty / html_safe / entities), and
 * Yajl::Projector#project over an in-memory IO of the re-encoded value (the Projector's own token-driven
 * parser over yajl_lex). Byte 0 picks options, byte 1 the chunk/read buffer size; the rest is JSON.
 *
 * Ruby exceptions (Yajl::ParseError, EncodeError, ...) are the API's normal error reporting and are
 * swallowed via rb_protect; memory errors in the C extension are caught by ASan/UBSan.
 *
 * The same source builds two targets:
 *  - ruby-parser-fuzzer (default): the Projector reads the Encoder's output for the parsed value
 *    (always well-formed JSON, in every pretty/html_safe/entities form, read in fuzzed buffer sizes),
 *    so fuzzing can explore the Projector's deeper states past the shallow abort below.
 *  - projector-fuzzer (-DPROJECTOR_FUZZER): the Projector reads the RAW input bytes (after the two
 *    option bytes), in fuzzed buffer sizes, exactly as it reads an untrusted stream in production.
 *    On malformed text (a lexer error token where a value is expected)
 *    rb_yajl_projector_build_simple_value reaches rb_bug("we should never get here") and aborts the
 *    process (mayhem/ruby-parser-fuzzer/known-findings/projector-rb-bug): this target reports that
 *    upstream bug as its defect, and fuzzes the Projector's lexer-error and truncated-token paths.
 *
 * The ruby VM is initialised once; each input only creates fresh Parser/Encoder/Projector objects,
 * so no state an input could change is carried to the next one (GC reclaims the garbage).
 */
#include <stddef.h>
#include <stdint.h>
#include <ruby.h>
#include <ruby/encoding.h>

void Init_yajl(void);

/* rb_bug() is ruby's internal assertion; yajl_ext.c calls it on "should never get here" paths
 * (rb_yajl_projector_build_*), and fuzzing reaches them. libruby's rb_bug prints a full VM crash
 * report (control frames, C backtrace via the ASan backtrace interceptor, /proc/self/maps, loaded
 * features) before aborting, and Mayhem's symbolic executor dies replaying that report. This
 * definition replaces libruby's for every caller (build.sh links with -Wl,--wrap=rb_bug, since libruby
 * is a static archive): same outcome (message + abort at the same frame, so the defect is still a
 * crash), without the report. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
void __wrap_rb_bug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("[BUG] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}

/* Ruby 3.3's ruby_init() starts a "timer thread" (rb_thread_create_timer_thread in thread_pthread.c:
 * eventfd + epoll + a pthread that time-slices ruby threads and delivers signals). This harness runs
 * one ruby thread and never needs it, and it is exactly the kind of timer thread a harness must not
 * carry: Mayhem's symbolic executor exited abnormally (1) on every run of this target ~50 s in, and
 * behavior testing then failed (ruby-parser-fuzzer runs 1-4, has_critical_errors). So thread creation
 * is refused while ruby_init() runs; ruby ignores pthread_create's result there (3.3 source), and runs
 * single-threaded. Outside that window every call is forwarded to the sanitizer's interceptor (or libc). */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
typedef int (*pthread_create_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern int __interceptor_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *)
    __attribute__((weak));
static int refuse_threads;
int pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *), void *arg) {
    static pthread_create_fn next;
    if (refuse_threads) return EAGAIN;
    if (!next) next = __interceptor_pthread_create ? __interceptor_pthread_create
                                                   : (pthread_create_fn)dlsym(RTLD_NEXT, "pthread_create");
    return next(t, attr, fn, arg);
}

/* Per-input work runs entirely through the C API (rb_funcall into yajl_ext.c's C methods): no Ruby
 * source is evaluated, neither at start-up (no `require`, no lib/yajl.rb) nor per input. Runs 1-5 of
 * this target evaluated a Ruby lambda per input; Mayhem's symbolic executor, which has to trace the
 * YARV interpreter for every bytecode of it, exited abnormally after ~6 tests on every run and failed
 * behavior testing (has_critical_errors). The calls below are the same public interface the gem's
 * Ruby code uses (Parser.new/parse/<<, Encoder.new/encode, Projector#project). */
static VALUE cParser, cEncoder, cProjector, cFuzzIO, cFuzzSink;
static ID id_new, id_parse, id_push, id_on_complete, id_encode, id_project, id_replace;
static ID iv_s, iv_p, iv_out, iv_stream, iv_bufsz;
static VALUE sym(const char *s) { return ID2SYM(rb_intern(s)); }

/* Ruby's GC marks the machine stack and registers CONSERVATIVELY: every word on the stack is looked up
 * as a possible object pointer. While an input is being processed those words include values derived
 * from the input, so under Mayhem's symbolic executor a GC turns into thousands of symbolic pointer
 * lookups into the object heap. Runs 1-6 of this target (with and without the timer thread, with and
 * without Ruby bytecode per input) all ended with the symbolic executor exiting abnormally a few tests
 * in. So the GC is disabled after ruby_init() (the heap grows instead) and collected explicitly only
 * every GC_EVERY inputs, at the start of an input before any of its data is touched. A symbolic-
 * execution test runs one input per process, so it never collects; libFuzzer's long-lived process does,
 * so its memory stays bounded. The input-to-output behaviour of every call below is unchanged.
 * Consequence (a known blind spot): a GC-marking bug in yajl_ext.c (a VALUE the parser/projector holds
 * but does not rb_gc_mark) can't show up in a single-input replay, and in libFuzzer only on the inputs
 * where a collection happens. mayhem/test.sh covers that class instead: it re-runs the parser, encoder
 * and projector specs under GC.stress. */
#define GC_EVERY 64
static unsigned long n_inputs;

/* FuzzIO#read(n, buf): the minimal IO the Projector needs (it only calls read(len, buf)). */
static VALUE fuzzio_read(int argc, VALUE *argv, VALUE self) {
    VALUE n, buf;
    rb_scan_args(argc, argv, "11", &n, &buf);
    VALUE s = rb_ivar_get(self, iv_s);
    long p = FIX2LONG(rb_ivar_get(self, iv_p)), len = RSTRING_LEN(s), want = NUM2LONG(n);
    if (want < 0) want = 0;
    if (p >= len) {
        if (!NIL_P(buf)) rb_funcall(buf, id_replace, 1, rb_str_new(NULL, 0));
        return Qnil;
    }
    if (want > len - p) want = len - p;
    VALUE c = rb_str_substr(s, p, want);
    rb_ivar_set(self, iv_p, LONG2FIX(p + want));
    if (!NIL_P(buf)) { rb_funcall(buf, id_replace, 1, c); return buf; }
    return c;
}

/* FuzzSink#call(obj): the on_parse_complete callback for chunked parsing. */
static VALUE fuzzsink_call(VALUE self, VALUE obj) {
    rb_ary_push(rb_ivar_get(self, iv_out), obj);
    return Qnil;
}

struct fuzz_ctx {
    int cfg, bufsz;
    VALUE json, obj, enc;
};

static VALUE do_parse(VALUE arg) {
    struct fuzz_ctx *c = (struct fuzz_ctx *)arg;
    VALUE opts = rb_hash_new();
    rb_hash_aset(opts, sym("symbolize_keys"), (c->cfg & 1) ? Qtrue : Qfalse);
    rb_hash_aset(opts, sym("allow_comments"), (c->cfg & 2) ? Qtrue : Qfalse);
    rb_hash_aset(opts, sym("check_utf8"), (c->cfg & 4) ? Qtrue : Qfalse);
    VALUE parser = rb_funcall(cParser, id_new, 1, opts);
    if (c->cfg & 8) {
        VALUE sink = rb_obj_alloc(cFuzzSink), out = rb_ary_new();
        rb_ivar_set(sink, iv_out, out);
        rb_funcall(parser, id_on_complete, 1, sink);
        long len = RSTRING_LEN(c->json);
        for (long i = 0; i < len; i += c->bufsz)
            rb_funcall(parser, id_push, 1, rb_str_substr(c->json, i, c->bufsz));
        c->obj = out;
    } else {
        c->obj = rb_funcall(parser, id_parse, 1, c->json);
    }
    return Qnil;
}

static VALUE do_encode(VALUE arg) {
    struct fuzz_ctx *c = (struct fuzz_ctx *)arg;
    VALUE opts = rb_hash_new();
    rb_hash_aset(opts, sym("pretty"), (c->cfg & 16) ? Qtrue : Qfalse);
    rb_hash_aset(opts, sym("html_safe"), (c->cfg & 32) ? Qtrue : Qfalse);
    rb_hash_aset(opts, sym("entities"), (c->cfg & 64) ? Qtrue : Qfalse);
    c->enc = rb_funcall(rb_funcall(cEncoder, id_new, 1, opts), id_encode, 1, c->obj);
    return Qnil;
}

static VALUE do_project(VALUE arg) {
    struct fuzz_ctx *c = (struct fuzz_ctx *)arg;
    VALUE io = rb_obj_alloc(cFuzzIO);
    rb_ivar_set(io, iv_s, c->enc);
    rb_ivar_set(io, iv_p, INT2FIX(0));
    /* Yajl::Projector#initialize (lib/yajl.rb) only sets these two ivars. */
    VALUE pr = rb_obj_alloc(cProjector);
    rb_ivar_set(pr, iv_stream, io);
    rb_ivar_set(pr, iv_bufsz, INT2FIX(c->bufsz));
    VALUE schema = Qnil;
    if (c->cfg & 128) {
        VALUE inner = rb_hash_new();
        rb_hash_aset(inner, rb_str_new_cstr("c"), Qnil);
        rb_hash_aset(inner, rb_str_new_cstr("d"), Qnil);
        schema = rb_hash_new();
        rb_hash_aset(schema, rb_str_new_cstr("a"), Qnil);
        rb_hash_aset(schema, rb_str_new_cstr("b"), inner);
    }
    rb_funcall(pr, id_project, 1, schema);
    return Qnil;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* argc lives in main()'s frame, above every frame libFuzzer later calls us from, so the GC's
     * conservative stack scan covers the whole stack. */
    ruby_init_stack((void *)argc);
    refuse_threads = 1;
    ruby_init();
    refuse_threads = 0;
    ruby_script("ruby_parser_fuzzer");
    rb_gc_disable();
    Init_yajl();
    VALUE mYajl = rb_const_get(rb_cObject, rb_intern("Yajl"));
    cParser = rb_const_get(mYajl, rb_intern("Parser"));
    cEncoder = rb_const_get(mYajl, rb_intern("Encoder"));
    cProjector = rb_const_get(mYajl, rb_intern("Projector"));
    cFuzzIO = rb_define_class("FuzzIO", rb_cObject);
    rb_define_method(cFuzzIO, "read", fuzzio_read, -1);
    cFuzzSink = rb_define_class("FuzzSink", rb_cObject);
    rb_define_method(cFuzzSink, "call", fuzzsink_call, 1);
    id_new = rb_intern("new"); id_parse = rb_intern("parse"); id_push = rb_intern("<<");
    id_on_complete = rb_intern("on_parse_complete="); id_encode = rb_intern("encode");
    id_project = rb_intern("project"); id_replace = rb_intern("replace");
    iv_s = rb_intern("@s"); iv_p = rb_intern("@p"); iv_out = rb_intern("@out");
    iv_stream = rb_intern("@stream"); iv_bufsz = rb_intern("@buffer_size");
    return 0;
}

static void maybe_gc(void) {
    if (++n_inputs % GC_EVERY == 0) {
        rb_gc_enable();
        rb_gc_start();
        rb_gc_disable();
    }
}

#ifdef PROJECTOR_FUZZER
/* projector-fuzzer: byte 0 bit 7 picks a schema (else nil = project everything), byte 1 the
 * Projector's buffer_size - 1; the rest is the stream, unfiltered. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    maybe_gc();
    struct fuzz_ctx c;
    c.cfg = data[0];
    c.bufsz = (int)data[1] + 1;
    c.json = Qnil;
    c.obj = Qnil;
    c.enc = rb_utf8_str_new((const char *)data + 2, (long)size - 2);
    int state = 0;
    rb_protect(do_project, (VALUE)&c, &state);  /* Yajl::ParseError etc. are normal errors */
    if (state) rb_set_errinfo(Qnil);
    RB_GC_GUARD(c.enc);
    return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    maybe_gc();
    struct fuzz_ctx c;
    c.cfg = data[0];
    c.bufsz = (int)data[1] + 1;
    c.json = rb_utf8_str_new((const char *)data + 2, (long)size - 2);
    c.obj = Qnil;
    c.enc = Qnil;
    /* Ruby exceptions (Yajl::ParseError, EncodeError, EncodingError, ...) are the API's normal error
     * reporting: swallowed, and later stages only run on what the earlier ones produced. */
    int parse_state = 0, state = 0;
    rb_protect(do_parse, (VALUE)&c, &parse_state);
    if (parse_state) rb_set_errinfo(Qnil);
    rb_protect(do_encode, (VALUE)&c, &state);
    if (state) { rb_set_errinfo(Qnil); c.enc = Qnil; }
    /* The Projector reads the Encoder's output (well-formed JSON), not the raw input: see the header. */
    if (!parse_state && RB_TYPE_P(c.enc, T_STRING) && rb_enc_str_coderange(c.enc) != ENC_CODERANGE_BROKEN) {
        rb_protect(do_project, (VALUE)&c, &state);
        if (state) rb_set_errinfo(Qnil);
    }
    RB_GC_GUARD(c.json);
    RB_GC_GUARD(c.obj);
    RB_GC_GUARD(c.enc);
    return 0;
}
#endif
