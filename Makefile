CFLAGS=-ggdb -fPIC -Wall -fvisibility=hidden

targets: libobstcp.a libobstcp.so.1 obstcp-serv obstcp-cli obstcp-redir

clean:
	rm -f *.o *.a *.pp

obstcp-redir: libobstcp.a obstcp-redir.c
	gcc $(CFLAGS) -o obstcp-redir obstcp-redir.c libobstcp.a -levent

obstcp-serv: libobstcp.a obstcp-serv.c
	gcc $(CFLAGS) -o obstcp-serv obstcp-serv.c libobstcp.a

obstcp-cli: libobstcp.a obstcp-cli.c
	gcc $(CFLAGS) -o obstcp-cli obstcp-cli.c libobstcp.a

libobstcp.so.1: libobstcp.o salsa20-merged.o sha256.o base64.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o
	gcc -o libobstcp.so.1 -shared -Wl,-soname -Wl,libobstcp.so.1 -ldl libobstcp.o salsa20-merged.o sha256.o base64.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o
	ln -sf libobstcp.so.1 libobstcp.so

libobstcp.a: libobstcp.o salsa20-merged.o sha256.o base64.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o
	ar -rc libobstcp.a libobstcp.o salsa20-merged.o sha256.o curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o base64.o

base64.o: base64.c
	gcc $(CFLAGS) -c base64.c

sha256.o: sha256.c
	gcc $(CFLAGS) -c sha256.c

libobstcp.o: libobstcp.c
	gcc $(CFLAGS) -c libobstcp.c

salsa20-x86-64.o: salsa20-amd64-xmm6.s
	as -o salsa20-x86-64.o salsa20-amd64-xmm6.s

salsa20-merged.o: salsa20-merged.c
	gcc $(CFLAGS) -c salsa20-merged.c

curve25519-donna-x86-64.s.o: curve25519-donna-x86-64.s.pp
	as -o curve25519-donna-x86-64.s.o curve25519-donna-x86-64.s.pp

curve25519-donna-x86-64.s.pp: curve25519-donna-x86-64.s
	cpp curve25519-donna-x86-64.s > curve25519-donna-x86-64.s.pp

curve25519-donna-x86-64.o: curve25519-donna-x86-64.c
	gcc $(CFLAGS) -c curve25519-donna-x86-64.c -Wall
