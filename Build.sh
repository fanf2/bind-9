#!/bin/sh

if [ -t 1 ]
then
	"$0" 2>&1 | tee -a Build.log
	exit $?
fi

echo SRCID=$(git rev-parse --short HEAD) >srcid

. version
PKG=bind-$MAJORVER.$MINORVER.$PATCHVER$RELEASETYPE$RELEASEVER
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

PATH_OpenSSL=/opt/OpenSSL-1.0.1g+0

export PYTHON=/opt/python-2.7.6+0/bin/python2.7

# Tell the configure script to link with the correct OpenSSL
LDFLAGS="-R$PATH_OpenSSL/lib"
export LDFLAGS

./configure --enable-threads --with-readline --with-pkcs11=no --with-libxml2=no \
	--with-openssl=$PATH_OpenSSL --without-gost --without-gssapi \
	--prefix=$PREFIX --mandir=$PREFIX/man \
	--localstatedir=/spool/bind/var \
	--sysconfdir=/spool/bind/etc

# suppress attempt to create $sysconfdir
touch installdirs

mkdir -p $PREFIX/bin $PREFIX/doc $PREFIX/man/man1
ln -s bin $PREFIX/sbin
cp ../nsdiff/nsdiff $PREFIX/bin
cp doc/arm/*.html doc/arm/Bv9ARM.pdf $PREFIX/doc

make all
make install

echo ==
echo ==  $(date +%Y-%m-%d.%H:%M:%S%z) $PREFIX done
echo ==
echo ========================================================================
