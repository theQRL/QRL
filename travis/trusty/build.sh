#!/bin/sh

set -e
cd /travis

sudo pip3 install -r requirements.txt
sudo pip3 install -r test-requirements.txt

pip3 install setuptools

if [ -n "${TEST:+1}" ]; then
    python3 setup.py test
fi
