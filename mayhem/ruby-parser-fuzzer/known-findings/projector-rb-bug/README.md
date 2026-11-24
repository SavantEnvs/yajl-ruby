# Yajl::Projector aborts the process on malformed JSON (rb_bug)

`Yajl::Projector.new(io).project(schema)` on text with a lexer error where a value is expected
(e.g. `{"c":d"...}`) reaches the `default:` case of `rb_yajl_projector_build_simple_value`
(`ext/yajl/yajl_ext.c:945`), which calls `rb_bug("we should never get here")`: the whole Ruby
process aborts instead of raising `Yajl::ParseError`. Found by Mayhem
(savantenvs/yajl-ruby, ruby-parser-fuzzer run 1, defect #3724423).

`crash-input.bin` reproduces it on the pre-guard harness (byte 0 = option bits, byte 1 = buffer
size - 1, then the JSON text). `ruby-parser-fuzzer` now only projects the Encoder's (well-formed) output for the parsed value, so
it can explore past this shallow bug; the `projector-fuzzer` target feeds the raw input to the
Projector and reports this abort as its defect (same input layout: `crash-input.bin` reproduces it there).
