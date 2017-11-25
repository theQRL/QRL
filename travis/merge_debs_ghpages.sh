#!/usr/bin/env bash
ls -lh
# Travis only clones the master branch, so I have to clone everything again to make sure I can switch branches.
mkdir merging_dir
git clone https://github.com/randomshinichi/QRL.git merging_dir/QRL
cd merging_dir/QRL
git remote -v
git branch -a

git checkout --track origin/xenial
mkdir ../xenial
cp -r results/* ../xenial/

git checkout --track origin/stretch
mkdir ../stretch
cp -r results/* ../stretch/

git checkout --track origin/gh-pages
rm -rf * .gitignore .travis.yml
mv  ../xenial ../stretch .

git add .
git commit -m "QRL release debs"
git push https://randomshinichi:$GITHUB_TOKEN@github.com/randomshinichi/QRL.git HEAD:gh-pages -f
