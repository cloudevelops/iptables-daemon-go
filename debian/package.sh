#!/bin/bash
rm $GOPATH/bin/iptables-daemon-go
go install
rm -rf /tmp/iptables-daemon-go
mkdir -p /tmp/iptables-daemon-go/usr/sbin
cp -a debian/root/* /tmp/iptables-daemon-go/
cp -a $GOPATH/bin/iptables-daemon-go /tmp/iptables-daemon-go/usr/sbin
fpm -s dir -t deb -C /tmp/iptables-daemon-go --name iptables-daemon-go --version 0.0.1 --iteration 2 --description "iptables management in go" --package /tmp/iptables-daemon-go

