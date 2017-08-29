#!/usr/bin/env sh
echo "Running pypi deployment script"
pip install -U pip
pip install -U setuptools
pip install -U twine
python setup.py bdist_wheel

export TWINE_USERNAME=${PYPI_USERNAME}

#### production deployment
#export TWINE_REPOSITORY=pypi
#export TWINE_PASSWORD=${PYPI_PASSWORD_PRODUCTION}

#### test deployment
export TWINE_REPOSITORY=pypitest
export TWINE_PASSWORD=${PYPI_PASSWORD_TEST}

twine upload --skip-existing ./dist/*
