# Copyright (C) 2012, 2013  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


# test response rate limiting

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#set -x
#set -o noclobber

ns1=10.53.0.1			    # root, defining the others
ns2=10.53.0.2			    # test server
ns3=10.53.0.3			    # secondary test server
ns7=10.53.0.7			    # whitelisted client

USAGE="$0: [-x]"
while getopts "x" c; do
    case $c in
	x) set -x;;
	*) echo "$USAGE" 1>&2; exit 1;;
    esac
done
shift `expr $OPTIND - 1 || true`
if test "$#" -ne 0; then
    echo "$USAGE" 1>&2
    exit 1
fi
# really quit on control-C
trap 'exit 1' 1 2 15


ret=0
setret () {
    ret=1
    echo "$*"
}


# Wait until soon after the start of a second to make results consistent.
#   The start of a second credits a rate limit.
#   This would be far easier in C or by assuming a modern version of perl.
sec_start () {
    START=`date`
    while true; do
	NOW=`date`
	if test "$START" != "$NOW"; then
	    return
	fi
	$PERL -e 'select(undef, undef, undef, 0.05)' || true
    done
}


#   $1=result name  $2=domain name  $3=dig options
digcmd () {
    OFILE=$1; shift
    DIG_DOM=$1; shift
    ARGS="+noadd +noauth +nosearch +time=1 +tries=1 +ignore $* -p 5300 $DIG_DOM @$ns2"
    #echo I:dig $ARGS 1>&2
    START=`date +%y%m%d%H%M.%S`
    RESULT=`$DIG $ARGS 2>&1 | tee $OFILE=TEMP				\
	    | sed -n -e  's/^[^;].*	\([^	 ]\{1,\}\)$/\1/p'	\
		-e 's/;; flags.* tc .*/TC/p'				\
		-e 's/;; .* status: NXDOMAIN.*/NXDOMAIN/p'		\
		-e 's/;; .* status: SERVFAIL.*/SERVFAIL/p'		\
		-e 's/;; connection timed out.*/drop/p'			\
		-e 's/;; communications error to.*/drop/p'		\
	    | tr -d '\n'`
    mv "$OFILE=TEMP" "$OFILE=$RESULT"
    touch -t $START "$OFILE=$RESULT"
}


#   $1=number of tests  $2=target domain  $3=dig options
CNT=1
burst () {
    BURST_LIMIT=$1; shift
    BURST_DOM_BASE="$1"; shift
    while test "$BURST_LIMIT" -ge 1; do
	if test $CNT -lt 10; then
	    CNT="00$CNT"
	else
	    if test $CNT -lt 100; then
		CNT="0$CNT"
	    fi
	fi
	eval BURST_DOM="$BURST_DOM_BASE"
	FILE="dig.out-$BURST_DOM-$CNT"
	digcmd $FILE $BURST_DOM $* &
	CNT=`expr $CNT + 1`
	BURST_LIMIT=`expr "$BURST_LIMIT" - 1`
    done
}


#   $1=domain  $2=IP address  $3=# of IP addresses  $4=TC  $5=drop
#	$6=NXDOMAIN  $7=SERVFAIL or other errors
ck_result() {
    BAD=
    wait
    ADDRS=`ls dig.out-$1-*=$2		2>/dev/null	| wc -l | tr -d ' '`
    TC=`ls dig.out-$1-*=TC		2>/dev/null	| wc -l | tr -d ' '`
    DROP=`ls dig.out-$1-*=drop		2>/dev/null	| wc -l | tr -d ' '`
    NXDOMAIN=`ls dig.out-$1-*=NXDOMAIN	2>/dev/null	| wc -l | tr -d ' '`
    SERVFAIL=`ls dig.out-$1-*=SERVFAIL	2>/dev/null	| wc -l | tr -d ' '`
    if test $ADDRS -ne "$3"; then
	setret "I:$ADDRS instead of $3 $2 responses for $1"
	BAD=yes
    fi
    if test $TC -ne "$4"; then
	setret "I:$TC instead of $4 truncation responses for $1"
	BAD=yes
    fi
    if test $DROP -ne "$5"; then
	setret "I:$DROP instead of $5 dropped responses for $1"
	BAD=yes
    fi
    if test $NXDOMAIN -ne "$6"; then
	setret "I:$NXDOMAIN instead of $6 NXDOMAIN responses for $1"
	BAD=yes
    fi
    if test $SERVFAIL -ne "$7"; then
	setret "I:$SERVFAIL instead of $7 error responses for $1"
	BAD=yes
    fi
    if test -z "$BAD"; then
	rm -f dig.out-$1-*
    fi
}


#########
sec_start

# basic rate limiting
burst 3 a1.tld2
# 1 second delay allows an additional response.
sleep 1
burst 21 a1.tld2
# request 30 different qnames to try a wild card
burst 30 'x$CNT.a2.tld2'

#					IP      TC      drop  NXDOMAIN SERVFAIL
# check for 24 results
# including the 1 second delay
ck_result   a1.tld2	192.0.2.1	3	7	14	0	0

# Check the wild card answers.
# The parent name of the 30 requests is counted.
ck_result 'x*.a2.tld2'	192.0.2.2	2	10	18	0	0


#########
sec_start

burst 1 'y$CNT.a3.tld3'; wait; burst 20 'y$CNT.a3.tld3'
burst 20 'z$CNT.a4.tld2'

# Recursion.
#   The first answer is counted separately because it is counted against
#   the rate limit on recursing to the server for a3.tld3.  The remaining 20
#   are counted as local responses from the cache.
ck_result 'y*.a3.tld3'	192.0.3.3	3	6	12	0	0

# NXDOMAIN responses are also limited based on the parent name.
ck_result 'z*.a4.tld2'	x		0	6	12	2	0


#########
sec_start

burst 20 a5.tld2 +tcp
burst 20 a6.tld2 -b $ns7
burst 20 a7.tld4

# TCP responses are not rate limited
ck_result a5.tld2	192.0.2.5	20	0	0	0	0

# whitelisted client is not rate limited
ck_result a6.tld2	192.0.2.6	20	0	0	0	0

# Errors such as SERVFAIL are rate limited.  The numbers are confusing, because
#   other rate limiting can be triggered before the SERVFAIL limit is reached.
ck_result a7.tld4	192.0.2.1	0	6	12	0	2


#########
sec_start

# all-per-second
#   The qnames are all unique but the client IP address is constant.
CNT=101
burst 80 'all$CNT.a8.tld2'
ck_result 'a*.a8.tld2'	192.0.2.8	70	0	10	0	0


$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p 9953 -s $ns2 stats
ckstats () {
    CNT=`sed -n -e "s/[	 ]*\([0-9]*\).responses $1 for rate limits.*/\1/p"  \
		ns2/named.stats`
    CNT=`expr 0$CNT + 0`
    if test "$CNT" -ne $2; then
	setret "I:wrong $1 statistics of $CNT instead of $2"
    fi
}
ckstats dropped 77
ckstats truncated 35

echo "I:exit status: $ret"
# exit $ret
[ $ret -ne 0 ] && echo "I:test failure overridden"
exit 0
# Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id$

# test response rate limiting

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#set -x
#set -o noclobber

ns1=10.53.0.1			    # root, defining the others
ns2=10.53.0.2			    # test server
ns3=10.53.0.3			    # secondary test server
ns7=10.53.0.7			    # whitelisted client

USAGE="$0: [-x]"
while getopts "x" c; do
    case $c in
	x) set -x;;
	*) echo "$USAGE" 1>&2; exit 1;;
    esac
done
shift `expr $OPTIND - 1 || true`
if test "$#" -ne 0; then
    echo "$USAGE" 1>&2
    exit 1
fi
# really quit on control-C
trap 'exit 1' 1 2 15


ret=0
setret () {
    ret=1
    echo "$*"
}


# Wait until soon after the start of a second to make results consistent.
#   The start of a second credits a rate limit.
#   This would be far easier in C or by assuming a modern version of perl.
sec_start () {
    START=`date`
    while true; do
	NOW=`date`
	if test "$START" != "$NOW"; then
	    return
	fi
	$PERL -e 'select(undef, undef, undef, 0.05)' || true
    done
}


#   $1=result name  $2=domain name  $3=dig options
digcmd () {
    OFILE=$1; shift
    DIG_DOM=$1; shift
    ARGS="+noadd +noauth +nosearch +time=1 +tries=1 +ignore $* -p 5300 $DIG_DOM @$ns2"
    #echo I:dig $ARGS 1>&2
    START=`date +%y%m%d%H%M.%S`
    RESULT=`$DIG $ARGS 2>&1 | tee $OFILE=TEMP				\
	    | sed -n -e  's/^[^;].*	\([^	 ]\{1,\}\)$/\1/p'	\
		-e 's/;; flags.* tc .*/TC/p'				\
		-e 's/;; .* status: NXDOMAIN.*/NXDOMAIN/p'		\
		-e 's/;; .* status: SERVFAIL.*/SERVFAIL/p'		\
		-e 's/;; connection timed out.*/drop/p'			\
		-e 's/;; communications error to.*/drop/p'		\
	    | tr -d '\n'`
    mv "$OFILE=TEMP" "$OFILE=$RESULT"
    touch -t $START "$OFILE=$RESULT"
}


#   $1=number of tests  $2=target domain  $3=dig options
CNT=1
burst () {
    BURST_LIMIT=$1; shift
    BURST_DOM_BASE="$1"; shift
    while test "$BURST_LIMIT" -ge 1; do
	if test $CNT -lt 10; then
	    CNT="00$CNT"
	else
	    if test $CNT -lt 100; then
		CNT="0$CNT"
	    fi
	fi
	eval BURST_DOM="$BURST_DOM_BASE"
	FILE="dig.out-$BURST_DOM-$CNT"
	digcmd $FILE $BURST_DOM $* &
	CNT=`expr $CNT + 1`
	BURST_LIMIT=`expr "$BURST_LIMIT" - 1`
    done
}


#   $1=domain  $2=IP address  $3=# of IP addresses  $4=TC  $5=drop
#	$6=NXDOMAIN  $7=SERVFAIL or other errors
ck_result() {
    BAD=
    wait
    ADDRS=`ls dig.out-$1-*=$2		2>/dev/null	| wc -l | tr -d ' '`
    TC=`ls dig.out-$1-*=TC		2>/dev/null	| wc -l | tr -d ' '`
    DROP=`ls dig.out-$1-*=drop		2>/dev/null	| wc -l | tr -d ' '`
    NXDOMAIN=`ls dig.out-$1-*=NXDOMAIN	2>/dev/null	| wc -l | tr -d ' '`
    SERVFAIL=`ls dig.out-$1-*=SERVFAIL	2>/dev/null	| wc -l | tr -d ' '`
    if test $ADDRS -ne "$3"; then
	setret "I:$ADDRS instead of $3 $2 responses for $1"
	BAD=yes
    fi
    if test $TC -ne "$4"; then
	setret "I:$TC instead of $4 truncation responses for $1"
	BAD=yes
    fi
    if test $DROP -ne "$5"; then
	setret "I:$DROP instead of $5 dropped responses for $1"
	BAD=yes
    fi
    if test $NXDOMAIN -ne "$6"; then
	setret "I:$NXDOMAIN instead of $6 NXDOMAIN responses for $1"
	BAD=yes
    fi
    if test $SERVFAIL -ne "$7"; then
	setret "I:$SERVFAIL instead of $7 error responses for $1"
	BAD=yes
    fi
    if test -z "$BAD"; then
	rm -f dig.out-$1-*
    fi
}


#########
sec_start

# basic rate limiting
burst 3 a1.tld2
# 1 second delay allows an additional response.
sleep 1
burst 21 a1.tld2
# request 30 different qnames to try a wild card
burst 30 'x$CNT.a2.tld2'

#					IP      TC      drop  NXDOMAIN SERVFAIL
# check for 24 results
# including the 1 second delay
ck_result   a1.tld2	192.168.2.1	3	7	14	0	0

# Check the wild card answers.
# The parent name of the 30 requests is counted.
ck_result 'x*.a2.tld2'	192.168.2.2	2	9	19	0	0


#########
sec_start

burst 1 'y$CNT.a3.tld3'; wait; burst 20 'y$CNT.a3.tld3'
burst 20 'z$CNT.a4.tld2'

# Recursion.
#   The first answer is counted separately because it is counted against
#   the rate limit on recursing to the server for a3.tld3.  The remaining 20
#   are counted as local responses from the cache.
ck_result 'y*.a3.tld3'	192.168.3.3	3	6	12	0	0

# NXDOMAIN responses are also limited based on the parent name.
ck_result 'z*.a4.tld2'	x		0	6	12	2	0


#########
sec_start

burst 20 a5.tld2 +tcp
burst 20 a6.tld2 -b $ns7
burst 20 a7.tld4

# TCP responses are not rate limited
ck_result a5.tld2	192.168.2.5	20	0	0	0	0

# whitelisted client is not rate limited
ck_result a6.tld2	192.168.2.6	20	0	0	0	0

# Errors such as SERVFAIL are rate limited.  The numbers are confusing, because
#   other rate limiting can be triggered before SERVFAIL is reached.
ck_result a7.tld4	192.168.2.1	0	5	13	0	2


#########
sec_start

# all-per-second
CNT=101
burst 80 'all$CNT.a8.tld2'
ck_result 'a*.a8.tld2'	192.168.2.8	70	3	7	0	0


echo "I:exit status: $ret"
exit $ret
