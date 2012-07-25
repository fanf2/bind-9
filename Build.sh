#!/bin/sh

if [ -t 1 ]
then exec "$0" 2>&1 | tee -a Build.log
fi

PKG=bind-9.9.2b1
VER=0
while :; do
	PREFIX=/opt/$PKG+$VER
	[ -d $PREFIX ] || break
	VER=`expr $VER + 1`
done

echo ========================================================================
echo ==
echo ==  $(date +%Y-%m-%d.%H:%M:%S%z) $PREFIX start
echo ==

PATH_OpenSSL=/opt/OpenSSL-1.0.0d+0

# Tell the configure script to link with the correct OpenSSL
LDFLAGS="-Wl,-R$PATH_OpenSSL/lib"
export LDFLAGS

./configure --enable-threads --with-openssl=$PATH_OpenSSL \
	--with-readline --without-gost --without-gssapi \
	--prefix=$PREFIX --mandir=$PREFIX/man \
	--localstatedir=/spool/bind/var \
	--sysconfdir=/spool/bind/etc

make -j3

# suppress attempt to create $sysconfdir
touch installdirs

mkdir -p $PREFIX/bin $PREFIX/doc
ln -s bin $PREFIX/sbin
cp doc/arm/*.html doc/arm/Bv9ARM.pdf $PREFIX/doc

make install

echo ==
echo ==  $(date +%Y-%m-%d.%H:%M:%S%z) $PREFIX done
echo ==
echo ========================================================================
