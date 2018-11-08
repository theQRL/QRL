#!/bin/bash

export TRAVIS_OS_NAME='linux'
export TEST='TRUE'
export PLATFORM='stretch'

#################
pushd . > /dev/null
cd $( dirname "${BASH_SOURCE[0]}" )
cd ..
function finish {
    popd > /dev/null
}
trap finish EXIT
#################

./travis/build.sh

