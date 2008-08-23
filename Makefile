CFLAGS=-ggdb -Wall

targets: libobstcp.a obstcp-nc

clean:
	rm -f *.o *.a *.pp

obstcp-nc: libobstcp.a obstcp-nc.c
	gcc $(CFLAGS) obstcp-nc.c libobstcp.a

libobstcp.a: libobstcp.o salsa20-x86-64.o sha256.o base64.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o
	ar -rc libobstcp.a libobstcp.o salsa20-x86-64.o sha256.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o base64.o

base64.o: base64.c
	gcc $(CFLAGS) -c base64.c

sha256.o: sha256.c
	gcc $(CFLAGS) -c sha256.c

libobstcp.o: libobstcp.c
	gcc $(CFLAGS) -c libobstcp.c

salsa20-x86-64.o: salsa20-amd64-xmm6.s
	as -o salsa20-x86-64.o salsa20-amd64-xmm6.s

curve25519-donna-x86-64.s.o: curve25519-donna-x86-64.s.pp
	as -o curve25519-donna-x86-64.s.o curve25519-donna-x86-64.s.pp

curve25519-donna-x86-64.s.pp: curve25519-donna-x86-64.s
	cpp curve25519-donna-x86-64.s > curve25519-donna-x86-64.s.pp

curve25519-donna-x86-64.o: curve25519-donna-x86-64.c
	gcc -O2 -c curve25519-donna-x86-64.c -Wall
