/*
 * yajl_ruby_main: a ruby interpreter with the yajl extension (ext/yajl, incl. yajl_ext.c) linked in
 * statically and registered as the "yajl/yajl" feature, so `require 'yajl'` (lib/yajl.rb) uses the
 * code compiled from this tree. mayhem/test.sh runs upstream's rspec suite with it.
 */
#include <ruby.h>

void Init_yajl(void);

int main(int argc, char **argv) {
    ruby_sysinit(&argc, &argv);
    {
        RUBY_INIT_STACK;
        ruby_init();
        Init_yajl();
        rb_provide("yajl/yajl.so"); /* lib/yajl.rb's `require 'yajl/yajl'` is now satisfied */
        return ruby_run_node(ruby_options(argc, argv));
    }
}
