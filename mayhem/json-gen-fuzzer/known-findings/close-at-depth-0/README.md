# yajl_gen: close at depth 0 corrupts the generator (OOB read)

`yajl_gen_map_close`/`yajl_gen_array_close` with nothing open run `DECREMENT_DEPTH`
(`ext/yajl/yajl_gen.c:180`): `--(g->depth)` wraps to `UINT_MAX`, the call returns
`yajl_depth_underflow`, but `depth` is left at `UINT_MAX`. The next generator call reads
`g->state[g->depth]` (`ENSURE_VALID_STATE`), far out of bounds of `state[YAJL_MAX_DEPTH]`:

    yajl_gen.c:324:5: runtime error: index 4294967295 out of bounds for type 'yajl_gen_state[256]'

`crash-input.bin` reproduces it on the pre-guard harness. The current `json_gen_fuzzer` only
issues a close while an open is outstanding so the target can explore past this shallow bug.

The mirror image is in `INCREMENT_DEPTH` (`yajl_gen.c:177`): the 256th nested `*_open` returns
`yajl_max_depth_exceeded` but leaves `depth == 256`, so the next call reads/writes
`g->state[256]` (`yajl_gen.c:338: index 256 out of bounds for type 'yajl_gen_state[256]'`). The
harness caps nesting at `YAJL_MAX_DEPTH - 1` for the same reason.
