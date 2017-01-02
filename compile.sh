c++ -DBIGARRAY_MULTIPLIER=1 -Wall -Werror -Wno-unknown-pragmas -fno-stack-protector -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_MAC -stdlib=libstdc++ -fomit-frame-pointer -fno-strict-aliasing -I../../include/pin/ -I../../include/pin/gen/ -I../../../extras/components/include -I../../../extras/xed-intel64/include -I../InstLib -c src/*.cpp

mkdir obj-intel64
mv *.o obj-intel64/

c++ -shared -w -Wl,-exported_symbols_list -Wl,../../include/pin/pintool.exp -stdlib=libstdc++ -o obj-intel64/main.dylib obj-intel64/*.o -L../../../intel64/lib -L../../../intel64/lib-ext -L../../../intel64/runtime/glibc -L../../../extras/xed-intel64/lib -lpin -lxed -lpindwarf
