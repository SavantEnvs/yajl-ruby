/*
 * json_reformat_fuzzer: parse JSON text with yajl_parse (fed in chunks) and re-emit every token
 * through the yajl_gen API, like yajl's json_reformat example. Reaches the lexer, parser, string
 * decoding (yajl_encode.c), the generator's string encoding incl. htmlSafe modes, yajl_buf growth,
 * yajl_parse_complete and the verbose error renderer (yajl_get_error).
 *
 * Byte 0 = config: bit0 allowComments, bit1 checkUTF8, bit2 beautify, bits3-4 htmlSafe (0..2),
 * bit5 use the raw yajl_number callback (else the integer/double callbacks), bits6-7 chunking.
 * Byte 1 = chunk size (1..256). The rest is the JSON text. Nothing is kept across inputs.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api/yajl_parse.h"
#include "api/yajl_gen.h"

#define G ((yajl_gen)ctx)

static int r_null(void *ctx) { return yajl_gen_null(G) == yajl_gen_status_ok; }
static int r_bool(void *ctx, int b) { return yajl_gen_bool(G, b) == yajl_gen_status_ok; }
static int r_int(void *ctx, long v) { return yajl_gen_integer(G, v) == yajl_gen_status_ok; }
static int r_double(void *ctx, double d) {
    yajl_gen_status s = yajl_gen_double(G, d);
    return s == yajl_gen_status_ok || s == yajl_gen_invalid_number;
}
static int r_number(void *ctx, const char *s, unsigned int l) {
    return yajl_gen_number(G, s, l) == yajl_gen_status_ok;
}
static int r_string(void *ctx, const unsigned char *s, unsigned int l) {
    return yajl_gen_string(G, s, l) == yajl_gen_status_ok;
}
static int r_map_open(void *ctx) { return yajl_gen_map_open(G) == yajl_gen_status_ok; }
static int r_map_close(void *ctx) { return yajl_gen_map_close(G) == yajl_gen_status_ok; }
static int r_arr_open(void *ctx) { return yajl_gen_array_open(G) == yajl_gen_status_ok; }
static int r_arr_close(void *ctx) { return yajl_gen_array_close(G) == yajl_gen_status_ok; }

static const yajl_callbacks cb_typed = {
    r_null, r_bool, r_int, r_double, NULL, r_string,
    r_map_open, r_string, r_map_close, r_arr_open, r_arr_close
};
static const yajl_callbacks cb_raw = {
    r_null, r_bool, NULL, NULL, r_number, r_string,
    r_map_open, r_string, r_map_close, r_arr_open, r_arr_close
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    uint8_t c = data[0];
    size_t chunk = (size_t)data[1] + 1;
    data += 2; size -= 2;

    yajl_parser_config pcfg = { c & 1, (c >> 1) & 1 };
    yajl_gen_config gcfg = { (c >> 2) & 1, "  ", ((c >> 3) & 3) % 3 };
    yajl_gen g = yajl_gen_alloc(&gcfg, NULL);
    yajl_handle h = yajl_alloc((c & 0x20) ? &cb_raw : &cb_typed, &pcfg, NULL, g);

    int mode = c >> 6;               /* 0: one shot, else chunks of `chunk` bytes */
    yajl_status st = yajl_status_ok;
    size_t off = 0;
    while (off < size) {
        size_t n = mode ? (size - off < chunk ? size - off : chunk) : size - off;
        st = yajl_parse(h, data + off, (unsigned int)n);
        if (st != yajl_status_ok && st != yajl_status_insufficient_data) break;
        off += n;
        /* drain the generator buffer as a streaming reformatter would */
        const unsigned char *buf; unsigned int len;
        if (yajl_gen_get_buf(g, &buf, &len) == yajl_gen_status_ok && mode == 3) yajl_gen_clear(g);
    }
    if (st == yajl_status_ok || st == yajl_status_insufficient_data)
        st = yajl_parse_complete(h);
    if (st != yajl_status_ok) {
        unsigned char *err = yajl_get_error(h, 1, data, (unsigned int)size);
        if (err) yajl_free_error(h, err);
    }
    const unsigned char *buf; unsigned int len;
    (void)yajl_gen_get_buf(g, &buf, &len);
    yajl_free(h);
    yajl_gen_free(g);
    return 0;
}
