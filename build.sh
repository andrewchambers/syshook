set -eux

CPPFLAGS="-D_XOPEN_SOURCE=700 -D_GNU_SOURCE"
CFLAGS="-std=c11 -Wall -Og -g"
LDLIBS="-lm -ldl"

gcc -o ./syshook $CPPFLAGS $CFLAGS $LDLIBS $(find . -name '*.c' | sort)