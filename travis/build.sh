#!/usr/bin/env bash

#set -xe

echo "TRAVIS_OS_NAME" ${TRAVIS_OS_NAME}
echo "PLATFORM" ${PLATFORM}



case "${TRAVIS_OS_NAME}" in
    osx)
        echo "UNSUPPORTED OS"
        exit 1
        brew install python3 swig
        brew outdated boost || brew upgrade boost
        brew outdated cmake || brew upgrade cmake
        sudo pip3 install -U pip setuptools twine | cat
        ;;

    linux)
        echo "LINUX BUILD " ${PLATFORM}

        USER_INFO="$( id -u ${USER} ):$( id -g ${USER} )"
        SHARE_USER_INFO="-v /etc/group:/etc/group:ro -v /etc/passwd:/etc/passwd:ro -u ${USER_INFO}"
        SHARE_SRC="-v $(pwd):/travis"

        docker stop $(docker ps -aq --filter name=builder) || true
        docker rm $(docker ps -aq --filter name=builder) || true
        docker build --file travis/Dockerfile.${PLATFORM} -t builder-${PLATFORM} .
        docker run -d --name builder ${SHARE_SRC} ${SHARE_USER_INFO} builder-${PLATFORM} tail -f /dev/null

        docker exec -t -e TEST -e DEPLOY builder /build.sh
        ;;
    *)
        echo ""
        echo "UNSUPPORTED OS"
        echo "You need to specify the TRAVIS_OS_NAME and PLATFORM"
        echo "Run: export TRAVIS_OS_NAME=..."
        echo ""
        echo "TRAVIS_OS_NAME -> linux, osx"
        echo "PLATFORM -> jessie, stretch, xenial"

        exit 1
        ;;
esac
