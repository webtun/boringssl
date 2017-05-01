#!/bin/sh

cd third_party/boringssl/src || exit 1

echo "fetching new commits..."
git fetch -v origin chromium-stable || exit 1
git checkout origin/chromium-stable || exit 1

echo "generating source files..."
cd .. || exit 1
python src/util/generate_build_files.py bazel || exit 1

echo "done!"
