#!/bin/bash

docker build -t pdfsignature:latest .

docker run -it --rm pdfsignature
