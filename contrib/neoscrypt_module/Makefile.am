ACLOCAL_AMFLAGS = -I build-aux/m4

lib_LTLIBRARIES = libneoscrypt.la
include_HEADERS = neoscrypt.h
noinst_HEADERS =


if USE_EXTERNAL_ASM
COMMON_LIB = neoscrypt_common.la
noinst_LTLIBRARIES = $(COMMON_LIB)
else
COMMON_LIB =
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = neoscrypt.pc


libneoscrypt_la_SOURCES =  neoscrypt.c
libneoscrypt_la_CPPFLAGS = -DNEOSCRYPT_BUILD -I$(top_srcdir)/include -I$(top_srcdir)
libneoscrypt_la_LIBADD = $(SECP_LIBS) $(COMMON_LIB)


noinst_PROGRAMS =


TESTS =


libneoscrypt_la_LDFLAGS = -no-undefined
LDFLAGS = -no-undefined
neoscrypt_la_LDFLAGS = -no-undefined -L/usr/lib/x86_64-linux-gnu/
LDFLAGS = -no-undefined 
neoscrypt_la_LDFLAGS = -no-undefined -L/usr/lib/x86_64-linux-gnu/
LDFLAGS = -no-undefined 
