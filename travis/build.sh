#!/usr/bin/env bash
docker exec -t -e CC_VER=${CC_VER} -e PLATFORM=${PLATFORM} builder /build.sh
