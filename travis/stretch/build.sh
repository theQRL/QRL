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

echo
echo
echo "****************************************************************"
echo "****************************************************************"
python --version
cmake --version
pip --version
pip3 --version
echo "****************************************************************"
echo "****************************************************************"
echo
echo

if [ -n "${TEST:+1}" ]; then
    echo "****************************************************************"
    echo "****************************************************************"
    echo "                            TEST"
    echo "****************************************************************"
    echo "****************************************************************"
    python3 setup.py test
fi

if [ -n "${DEPLOY:+1}" ]; then
    echo "****************************************************************"
    echo "****************************************************************"
    echo "                           DEPLOY"
    echo "****************************************************************"
    echo "****************************************************************"
    python3 setup.py sdist
fi

if [ -n "${BUILD_DIST:+1}" ]; then
   echo "****************************************************************"
   echo "****************************************************************"
   echo "                          BUILD_DIST"
   echo "****************************************************************"
   echo "****************************************************************"

   tar xvf keys.tar
   gpg --import public.gpg || true
   gpg --import private.gpg || true

   mkdir -p /travis/distro
   cd /travis/distro
   pip3 download --no-deps qrl
   export QRL_SLUG=$(ls qrl-* | sed 's/.tar.gz//')
   echo "QRL_SLUG: ${QRL_SLUG}"
   py2dsc --with-python2=False --with-python3=True ${QRL_SLUG}.tar.gz
   cd deb_dist/${QRL_SLUG}
   echo 'export DEB_BUILD_OPTIONS=nocheck' >> debian/rules
   dpkg-buildpackage -k$GPGKEY

   # cleanup compile time files otherwise git will add them to the repo too!
   cd /travis/distro/deb_dist
   rm -rf ${QRL_SLUG}
fi
