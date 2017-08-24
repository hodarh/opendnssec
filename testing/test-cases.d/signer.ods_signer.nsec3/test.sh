#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start OpenDNSSEC
echo -n "LINE: ${LINENO} " && ods_start_ods-control &&

## Check NSEC3 chain
echo -n "LINE: ${LINENO} " && sed < ./zonefile-a > "$INSTALL_ROOT/var/opendnssec/unsigned/ods0" -e 's/SERIAL/1001/g;s/ods./ods0./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods0 -p optin &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods0 serial 1001*' &&
echo -n "LINE: ${LINENO} " && validns "$INSTALL_ROOT/var/opendnssec/signed/ods0" &&

echo -n "LINE: ${LINENO} " && sed < "$INSTALL_ROOT/var/opendnssec/signed/ods0" > "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad" -e 's/gtefkl93okrfunnbafbh3r6nsfal05o8.ods0./qtefkl93okrfunnbafbh3r6nsfal05o8.ods0./g' &&
echo -n "LINE: ${LINENO} " && ! log_this validns-badnsec3 validns "$INSTALL_ROOT/var/opendnssec/signed/ods0-bad" &&
echo -n "LINE: ${LINENO} " && log_grep validns-badnsec3 stderr "broken NSEC3 chain, expected gtefkl93okrfunnbafbh3r6nsfal05o8.ods0., but found" &&
echo -n "LINE: ${LINENO} " && log_grep validns-badnsec3 stderr "no corresponding NSEC3 found for ods0." &&

## Opt-in vs opt-out
echo -n "LINE: ${LINENO} " && sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods1" -e 's/SERIAL/1001/g;s/ods./ods1./g' &&
echo -n "LINE: ${LINENO} " && sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods2" -e 's/SERIAL/1001/g;s/ods./ods2./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods1 -p optin &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods2 -p optout &&


echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods1 serial 1001*' &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods2 serial 1001*' &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 ods1.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 0 5 -.* A NS SOA MX RRSIG DNSKEY NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/ods1" &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 ods2.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods2.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.* A NS SOA MX RRSIG DNSKEY NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/ods2" &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 aaa.ods1.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods1.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 0 5 -.* NS" $INSTALL_ROOT/var/opendnssec/signed/ods1 &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 aaa.ods2.` &&
echo -n "LINE: ${LINENO} " && ! grep "${hash}ods2.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.* NS" $INSTALL_ROOT/var/opendnssec/signed/ods2 &&

echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods1 &&
echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods2 &&

## Insecure delegation
echo -n "LINE: ${LINENO} " && sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods3" -e 's/SERIAL/1001/g;s/ods./ods3./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods3 -p optout &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods3 serial 1001*' &&
echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 aaa.ods3.` &&
echo -n "LINE: ${LINENO} " && ! grep "${hash}ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 0 5 -.* NS" $INSTALL_ROOT/var/opendnssec/signed/ods3 &&

## Secure delegation
echo "Update ods3, add DS and wait for signed zone" &&
echo -n "LINE: ${LINENO} " && sed < ./zonefile-c > "$INSTALL_ROOT/var/opendnssec/unsigned/ods3" -e 's/SERIAL/1002/g;s/ods./ods3./g' &&
echo -n "LINE: ${LINENO} " && ods-signer sign ods3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods3 serial 1002*' &&
sleep 10 &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 aaa.ods3.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods3.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.* NS DS RRSIG" $INSTALL_ROOT/var/opendnssec/signed/ods3 &&

echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods3 &&

## Empty non-terminal
echo -n "LINE: ${LINENO} " && sed < ./zonefile-d > "$INSTALL_ROOT/var/opendnssec/unsigned/ods4" -e 's/SERIAL/1001/g;s/ods./ods4./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods4 -p optout &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods4 serial 1001*' &&

echo "Check if empty non-terminal NSEC3s are added" &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 on.ods4.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods4.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods4" &&
echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 ottawa.on.ods4.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods4.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods4" &&

echo -n "LINE: ${LINENO} " && validns $INSTALL_ROOT/var/opendnssec/signed/ods4 &&

## Empty non-terminal derived from an insecure delegation
echo -n "LINE: ${LINENO} " && sed < ./zonefile-e > "$INSTALL_ROOT/var/opendnssec/unsigned/ods5" -e 's/SERIAL/1001/g;s/ods./ods5./g' &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods5 -p optout &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods5 serial 1001*' &&

## RFC 7129: Always provide empty non-terminals with an NSEC3 record, even if it is only derived from an insecure delegation
## Unlike bind, ODS provides NSEC3 for empty non-terminals from insecure delegations
echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 on.ods5.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods5.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods5" &&
echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 ottawa.on.ods5.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods5.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods5" &&

## Secure delegation
echo "Update ods5, add DS and wait for signed zone" &&
echo -n "LINE: ${LINENO} " && sleep 2 &&
echo -n "LINE: ${LINENO} " && sed < ./zonefile-f > "$INSTALL_ROOT/var/opendnssec/unsigned/ods5" -e 's/SERIAL/1002/g;s/ods./ods5./g' &&
echo -n "LINE: ${LINENO} " && ods-signer sign ods5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods5 serial 1002*' &&

echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 on.ods5.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods5.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods5" &&
echo -n "LINE: ${LINENO} " && hash=`ldns-nsec3-hash -a 1 -t 5 ottawa.on.ods5.` &&
echo -n "LINE: ${LINENO} " && grep "${hash}ods5.[[:space:]]*3600[[:space:]]*IN[[:space:]]*NSEC3[[:space:]]*1 1 5 -.*" "$INSTALL_ROOT/var/opendnssec/signed/ods5" &&


## Stop
ods_stop_ods-control && 
return 0

ods_kill
return 1
