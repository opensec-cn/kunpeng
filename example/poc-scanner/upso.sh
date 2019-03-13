#!/bin/bash

set -e
set -x
KUNPENG_SRC="$GOPATH/src/github.com/opensec-cn/kunpeng"
CWD=`pwd`

cd ${KUNPENG_SRC} 

git fetch --all 

go install ./vendor/github.com/mjibson/esc
esc -include="\.json" -o plugin/json/JSONPlugin.go -pkg jsonplugin plugin/json/
go build -buildmode=c-shared --ldflags="-w -s" -o kunpeng_c.so
cp kunpeng_c.so ${CWD}/so/kunpeng_c.so
supervisorctl restart poc_scanner
