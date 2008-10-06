CFLAGS=-ggdb -fPIC -Wall -fvisibility=hidden
TARGETS=.warning libobstcp.a libobstcp.so.1 obstcp-serv obstcp-cli obstcp-redir obstcp-keygen

targets: $(TARGETS)

.warning:
	cat build-note
	sleep 7
	touch .warning

install: libobstcp.so.1 libobstcp.h
	cp libobstcp.h /usr/include
	cp libobstcp.so.1 /usr/lib
	ln -sf /usr/lib/libobstcp.so.1 /usr/lib/libobstcp.so
	ldconfig

clean:
	rm -f *.o *.a *.pp $(TARGETS)

obstcp-redir: libobstcp.a obstcp-redir.c
	gcc $(CFLAGS) -o obstcp-redir obstcp-redir.c libobstcp.a curve25519.a -levent

obstcp-serv: libobstcp.a obstcp-serv.c
	gcc $(CFLAGS) -o obstcp-serv obstcp-serv.c libobstcp.a curve25519.a

obstcp-cli: libobstcp.a obstcp-cli.c
	gcc $(CFLAGS) -o obstcp-cli obstcp-cli.c libobstcp.a curve25519.a

obstcp-keygen: obstcp-keygen.c libobstcp.a
	gcc $(CFLAGS) -o obstcp-keygen obstcp-keygen.c libobstcp.a curve25519.a

libobstcp.so.1: libobstcp.o salsa208.o sha256.o base32.o curve25519.a cursor.h varbuf.h iovec_cursor.h
	gcc -o libobstcp.so.1 -shared -Wl,-soname -Wl,libobstcp.so.1 -ldl libobstcp.o salsa208.o sha256.o base32.o curve25519.a

libobstcp.a: libobstcp.o salsa208.o sha256.o base32.o curve25519.a cursor.h varbuf.h iovec_cursor.h
	ar -rc libobstcp.a libobstcp.o salsa208.o sha256.o base32.o

base32.o: base32.c
	gcc $(CFLAGS) -c base32.c

sha256.o: sha256.c
	gcc $(CFLAGS) -c sha256.c

libobstcp.o: libobstcp.c
	gcc $(CFLAGS) -c libobstcp.c

salsa208.o: salsa208.c
	gcc $(CFLAGS) -c salsa208.c

curve25519.a:
	/bin/bash -c 'cd curve25519 && exec /bin/bash buildone.sh'
