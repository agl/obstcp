#!/bin/sh

set -u
set -e

# The first one to build correctly is used, so this is a priority order
for x in donna athlon donna_c64 ; do
  echo "Trying $x"
  ok=1
  cd $x \
  && for f in $(ls *.s *.c); do
       gcc -O3 -fvisibility=hidden -fPIC -fomit-frame-pointer -c $f || ok=0
     done \
  && [ "$ok" -eq 1 ] \
  && gcc ../test.c *.o \
  && ./a.out \
  && rm -f ../curve25519.a \
  && ar r ../../curve25519.a *.o \
  && echo "Built $x" \
  && exit 0

  cd ..
done

echo "Sorry, all curve25519 implementations failed to build"
exit 1
