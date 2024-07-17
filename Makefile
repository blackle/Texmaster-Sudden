CFLAGS ?= -Wall -Og -g

libsudden.so: libsudden.c Makefile
	$(CC) $(CFLAGS) -fPIC -rdynamic -shared -ldl -o $@ libsudden.c