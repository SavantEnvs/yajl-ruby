/*
 * json_gen_fuzzer: drive the yajl_gen API (the encoder half of yajl, used by Yajl::Encoder) with an
 * opcode stream: yajl_gen.c's state machine (key/value states, nesting, error and complete states),
 * yajl_string_encode2 over raw, unvalidated bytes in every htmlSafe mode, number formatting, and
 * yajl_buf growth or the print-callback path.
 *
 * Byte 0 = config: bit0 beautify, bits1-2 htmlSafe (0..2), bit3 print callback (yajl_gen_alloc2)
 * instead of the internal buffer. Then one opcode byte per call; string/number ops take a
 * one-byte length followed by that many bytes. Status codes are ignored on purpose: calling the
 * API in the wrong state is part of what is being fuzzed (except the depth under/overflow, see below). Nothing is kept across inputs.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api/yajl_gen.h"

#define MAX_OPEN (YAJL_MAX_DEPTH - 1)

static void sink(void *ctx, const char *str, unsigned int len) {
    size_t *total = (size_t *)ctx;
    if (len) *total += (unsigned char)str[0] + (unsigned char)str[len - 1];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t c = data[0];
    size_t i = 1;
    size_t total = 0;
    unsigned int open = 0;  /* containers successfully opened and not yet closed */
    yajl_gen_config cfg = { c & 1, (c & 0x10) ? "\t" : "  ", ((c >> 1) & 3) % 3 };
    yajl_gen g = (c & 8) ? yajl_gen_alloc2(sink, &cfg, NULL, &total)
                         : yajl_gen_alloc(&cfg, NULL);
    if (!g) return 0;

    while (i < size) {
        uint8_t op = data[i++];
        switch (op % 14) {
        case 0: (void)yajl_gen_null(g); break;
        case 1: (void)yajl_gen_bool(g, op & 0x80); break;
        /* Closes are only issued while a successful open is outstanding: a close at depth 0
         * underflows g->depth (DECREMENT_DEPTH returns yajl_depth_underflow but leaves depth at
         * UINT_MAX), and the next call reads g->state[UINT_MAX]. That is a known upstream bug
         * (mayhem/json-gen-fuzzer/known-findings/close-at-depth-0); without this guard almost
         * every input hits it within a few executions and nothing deeper is explored. Opens are
         * likewise capped below YAJL_MAX_DEPTH: the 256th open leaves depth at 256 after
         * INCREMENT_DEPTH fails, and the next call indexes g->state[256] (same known finding). */
        case 2: if (open < MAX_OPEN && yajl_gen_map_open(g) == yajl_gen_status_ok) open++; break;
        case 3: if (open && yajl_gen_map_close(g) == yajl_gen_status_ok) open--; break;
        case 4: if (open < MAX_OPEN && yajl_gen_array_open(g) == yajl_gen_status_ok) open++; break;
        case 5: if (open && yajl_gen_array_close(g) == yajl_gen_status_ok) open--; break;
        case 6: case 7: {             /* string (map keys and values) */
            size_t n = i < size ? data[i++] : 0;
            if (n > size - i) n = size - i;
            (void)yajl_gen_string(g, data + i, (unsigned int)n);
            i += n;
            break;
        }
        case 8: {                     /* raw number text, unvalidated */
            size_t n = i < size ? data[i++] : 0;
            if (n > size - i) n = size - i;
            (void)yajl_gen_number(g, (const char *)data + i, (unsigned int)n);
            i += n;
            break;
        }
        case 9: case 10: case 11: {   /* integer / long / double from 8 input bytes */
            uint8_t b[8] = {0};
            size_t n = size - i < 8 ? size - i : 8;
            memcpy(b, data + i, n);
            i += n;
            long l; double d;
            memcpy(&l, b, sizeof l < 8 ? sizeof l : 8);
            memcpy(&d, b, 8);
            if (op % 14 == 9) (void)yajl_gen_integer(g, l);
            else if (op % 14 == 10) (void)yajl_gen_long(g, l);
            else (void)yajl_gen_double(g, d);
            break;
        }
        case 12: {
            const unsigned char *buf; unsigned int len;
            if (yajl_gen_get_buf(g, &buf, &len) == yajl_gen_status_ok && len)
                total += buf[0] + buf[len - 1];
            break;
        }
        case 13: yajl_gen_clear(g); break;
        }
    }
    const unsigned char *buf; unsigned int len;
    if (yajl_gen_get_buf(g, &buf, &len) == yajl_gen_status_ok && len)
        total += buf[len - 1];
    yajl_gen_free(g);
    return total == (size_t)-1;
}
