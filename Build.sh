#!/bin/sh

PREFIX=/opt/bind-9.9.1-P1+fanf

PATH_OpenSSL=/opt/OpenSSL-1.0.0d+0

# Tell the configure script to link with the correct OpenSSL
LDFLAGS="-Wl,-R$PATH_OpenSSL/lib"
export LDFLAGS

./configure --enable-threads --with-openssl=$PATH_OpenSSL \
	--with-readline --without-gost --without-gssapi \
	--prefix=$PREFIX --mandir=$PREFIX/man \
	--localstatedir=/spool/bind/var \
	--sysconfdir=/spool/bind/etc

rm -rf $PREFIX
mkdir -p $PREFIX/bin
ln -s bin $PREFIX/sbin

make install
