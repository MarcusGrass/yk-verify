#!/bin/sh
# Make sure target exist so we don't get annoying permission trouble
mkdir -p target && \
# Build container
docker build . -f .docker/Dockerfile -t yk-verify-local && \
# Run with target mounted
docker run -v $(pwd)/target:/yk/target --user 1000:1000 yk-verify-local