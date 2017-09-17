#!/bin/sh

set -e
cd /travis

pip3 install -U coverage
pip3 install -r requirements.txt
pip3 install -r test-requirements.txt

pip3 install setuptools

python3 setup.py test
