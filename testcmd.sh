#!/bin/bash

apache2ctl -t
service apache2 restart
go test "$@" ./...
