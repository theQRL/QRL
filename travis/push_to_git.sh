set -e

echo "PUSHING TO GITHUB PAGES"
if [ `git rev-parse --quiet --verify ${PLATFORM}` > /dev/null ]
then
    echo "Branch ${PLATFORM} already exists, deleting"
    git branch -D ${PLATFORM}
fi

git checkout --orphan ${PLATFORM}
git rm -rf .
git add distro/deb_dist
git commit -m "QRL binaries"
git push https://randomshinichi:$GITHUB_TOKEN@github.com/randomshinichi/QRL HEAD:${PLATFORM} -f

