# http://pcsclite.alioth.debian.org/pcsclite.html

CFLAGS += -g $(shell pkg-config --cflags libpcsclite)
LDLIBS += $(shell pkg-config --libs libpcsclite)

test_cr: test_cr.o pcsc_cr.o ykneo.o
