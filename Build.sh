#!/bin/sh

PREFIX=/opt/bind-9.9.1-P2+fanf

PATH_OpenSSL=/opt/OpenSSL-1.0.0d+0

# Tell the configure script to link with the correct OpenSSL
LDFLAGS="-Wl,-R$PATH_OpenSSL/lib"
export LDFLAGS

./configure --enable-threads --with-openssl=$PATH_OpenSSL \
	--with-readline --without-gost --without-gssapi \
	--prefix=$PREFIX --mandir=$PREFIX/man \
	--localstatedir=/spool/bind/var \
	--sysconfdir=/spool/bind/etc

make -j8

# suppress attempt to create $sysconfdir
touch installdirs

mkdir -p $PREFIX/bin $PREFIX/doc
ln -s bin $PREFIX/sbin
cp doc/arm/*.html doc/arm/Bv9ARM.pdf $PREFIX/doc

make install

# done
