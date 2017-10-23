#!/bin/sh

set -e

echo "Creating/fixing home"
sudo mkdir -p ${HOME}
sudo -E chown -R $(whoami):$(whoami) ${HOME}
sudo -E chmod -R a+rxw ${HOME}

cd /travis

sudo -H pip3 install -r requirements.txt
sudo -H pip3 install -r test-requirements.txt
sudo -H pip3 install setuptools

if [ -n "${TEST:+1}" ]; then
    python3 setup.py test
fi

if [ -n "${DEPLOY:+1}" ]; then
    python3 setup.py sdist
fi
