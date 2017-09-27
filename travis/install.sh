#!/bin/sh

if [ -z "${PLATFORM}" ]
then
   echo "PLATFORM has not been set"
   exit 1
fi

USER_INFO="$( id -u ${USER} ):$( id -g ${USER} )"
SHARE_USER_INFO="-v /etc/group:/etc/group:ro -v /etc/passwd:/etc/passwd:ro -u ${USER_INFO}"
USER_INFO=''
SHARE_USER_INFO=''
SHARE_SRC="-v $(pwd):/travis"

docker build --file travis/Dockerfile.${PLATFORM} -t builder-${PLATFORM} .
docker run -d --name builder ${SHARE_SRC} ${SHARE_USER_INFO} builder-${PLATFORM} tail -f /dev/null
