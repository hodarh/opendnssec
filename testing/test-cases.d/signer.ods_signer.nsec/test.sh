#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start OpenDNSSEC
echo -n "LINE: ${LINENO} " && ods_start_ods-control &&

## Check NSEC chain
echo -n "LINE: ${LINENO} " && sed < ./zonefile-a > "$INSTALL_ROOT/var/opendnssec/unsigned/ods0" -e 's/SERIAL/1001/g;s/ods./ods0./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods0 &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods0 serial 1001*' &&

echo -n "LINE: ${LINENO} " && grep "ods0.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*aaa.ods0. A NS SOA MX RRSIG NSEC DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods0" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ods0.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*mail.ods0. A RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods0" &&
echo -n "LINE: ${LINENO} " && validns "$INSTALL_ROOT/var/opendnssec/signed/ods0" &&

## Bad NSEC
echo -n "LINE: ${LINENO} " && sed < "$INSTALL_ROOT/var/opendnssec/signed/ods0" > "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad-1" -e 's/aaa.ods0. A NS SOA MX RRSIG NSEC DNSKEY/aaa.ods0. A NS SOA RRSIG NSEC DNSKEY/g' &&
echo -n "LINE: ${LINENO} " && ! log_this validns-badnsec_1 validns "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad-1" &&
echo -n "LINE: ${LINENO} " && log_grep validns-badnsec_1 stderr "MX exists, but NSEC does not mention it for ods0." &&
echo -n "LINE: ${LINENO} " && (log_grep validns-badnsec_1 stderr "ods0. RRSIG(NSEC): cannot verify the signature" ||
			       log_grep validns-badnsec_1 stderr "ods0. RRSIG(NSEC): bad signature") &&

echo -n "LINE: ${LINENO} " && sed < "$INSTALL_ROOT/var/opendnssec/signed/ods0" > "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad-2" -e 's/aaa.ods0. A NS SOA MX RRSIG NSEC DNSKEY/aaaa.ods0. A NS SOA MX RRSIG NSEC DNSKEY/g' &&
echo -n "LINE: ${LINENO} " && ! log_this validns-badnsec_2 validns "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad-2" &&
echo -n "LINE: ${LINENO} " && log_grep validns-badnsec_2 stderr "NSEC says aaaa.ods0. comes after ods0., but aaa.ods0. does" &&
echo -n "LINE: ${LINENO} " && log_grep validns-badnsec_2 stderr "broken NSEC chain" &&
echo -n "LINE: ${LINENO} " && (log_grep validns-badnsec_2 stderr "ods0. RRSIG(NSEC): cannot verify the signature" ||
			       log_grep validns-badnsec_2 stderr "ods0. RRSIG(NSEC): bad signature") &&

## Insecure delegation
echo -n "LINE: ${LINENO} " && sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods1" -e 's/SERIAL/1001/g;s/ods./ods1./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods1 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods1 serial 1001*' &&

echo -n "LINE: ${LINENO} " && grep "ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*aaa.ods1. A NS SOA MX RRSIG NSEC DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods1" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*mail.ods1. NS RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods1" &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods1 &&


## Secure delegation
echo "Update ods1, add DS and wait for signed zone" &&
echo -n "LINE: ${LINENO} " && sed < ./zonefile-c > "$INSTALL_ROOT/var/opendnssec/unsigned/ods1" -e 's/SERIAL/1002/g;s/ods./ods1./g' &&
echo -n "LINE: ${LINENO} " && ods-signer sign ods1 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods1 serial 1002*' &&
sleep 10 &&

echo -n "LINE: ${LINENO} " && grep "ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*aaa.ods1. A NS SOA MX RRSIG NSEC DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods1" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*mail.ods1. NS DS RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods1" &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods1 &&

## Empty non-terminal: no NSEC for empty non-terminal
echo -n "LINE: ${LINENO} " && sed < ./zonefile-d > "$INSTALL_ROOT/var/opendnssec/unsigned/ods2" -e 's/SERIAL/1001/g;s/ods./ods2./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods2 &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods2 serial 1001*' &&

echo "Check if empty non-terminal NSECs are added" &&
echo -n "LINE: ${LINENO} " && ! grep "^on.ods2.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods2" &&
echo -n "LINE: ${LINENO} " && ! grep "^ottawa.on.ods2.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods2" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ottawa.on.ods2.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*bbb.ottawa.on.ods2. A RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods2" &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods2 &&

## Empty non-terminal derived from an insecure delegation
echo -n "LINE: ${LINENO} " && sed < ./zonefile-e > "$INSTALL_ROOT/var/opendnssec/unsigned/ods3" -e 's/SERIAL/1001/g;s/ods./ods3./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods3 &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods3 serial 1001*' &&

echo -n "LINE: ${LINENO} " && ! grep "^on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && ! grep "^ottawa.on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ottawa.on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*ods3. NS RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods3 &&

## Empty non-terminal derived from a secure delegation
echo "Update ods3, add DS and wait for signed zone" &&
echo -n "LINE: ${LINENO} " && sleep 2 &&
echo -n "LINE: ${LINENO} " && sed < ./zonefile-f > "$INSTALL_ROOT/var/opendnssec/unsigned/ods3" -e 's/SERIAL/1002/g;s/ods./ods3./g' &&
echo -n "LINE: ${LINENO} " && ods-signer sign ods3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods3 serial 1002*' &&

echo -n "LINE: ${LINENO} " && ! grep "^on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && ! grep "^ottawa.on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && grep "aaa.ottawa.on.ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC[[:space:]]*ods3. NS DS RRSIG NSEC" "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods3 &&

## Stop
ods_stop_ods-control && 
return 0

ods_kill
return 1

