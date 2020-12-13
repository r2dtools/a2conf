#!/bin/bash

docker run --volume="$(pwd):/opt/a2conf" a2conf-tests
