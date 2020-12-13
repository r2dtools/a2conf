#!/bin/bash

service apache2 restart
go test "$@" ./...
