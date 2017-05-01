#!/bin/sh

cd third_party/boringssl/src || exit 1

echo "fetching new commits..."
git fetch origin chromium-stable || exit 1

LOCAL=$(git rev-parse @)
echo "local: $LOCAL"

REMOTE=$(git rev-parse origin/chromium-stable)
echo "remote: $LOCAL"

if [ $LOCAL = $REMOTE ]; then
    echo "Up-to-date"
    exit 0
fi

git checkout origin/chromium-stable || exit 1

echo "generating source files..."
cd .. || exit 1
python src/util/generate_build_files.py bazel || exit 1

echo "commiting..."
SHORT_REV=$(echo $REMOTE | cut -c1-6)
COMMIT_MSG="Roll $SHORT_REV"

git add . || exit 1
git commit -m "$COMMIT_MSG" || exit 1

echo "done!"
