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

PATH_OpenSSL=/opt/OpenSSL-1.0.1e+0

export PYTHON=/opt/python-3.3.3+0/bin/python3.3

# Tell the configure script to link with the correct OpenSSL
LDFLAGS="-Wl,-R$PATH_OpenSSL/lib"
export LDFLAGS

./configure --enable-threads --with-readline \
	--with-openssl=$PATH_OpenSSL --without-gost --without-gssapi \
	--prefix=$PREFIX --mandir=$PREFIX/man \
	--localstatedir=/spool/bind/var \
	--sysconfdir=/spool/bind/etc

perl -pi -e 's#define HAVE_REGEX_H 1#undef HAVE_REGEX_H#' config.h

make -j3

# suppress attempt to create $sysconfdir
touch installdirs

mkdir -p $PREFIX/bin $PREFIX/doc
ln -s bin $PREFIX/sbin
cp doc/arm/*.html doc/arm/Bv9ARM.pdf $PREFIX/doc

make install

cd $PREFIX/man
ln -s man[158]/* .

echo ==
echo ==  $(date +%Y-%m-%d.%H:%M:%S%z) $PREFIX done
echo ==
echo ========================================================================
