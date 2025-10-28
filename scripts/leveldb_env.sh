#!/bin/bash
# LevelDB Environment Variables
# Source this file before building Python packages that depend on LevelDB
# Usage: source scripts/leveldb_env.sh

export CPLUS_INCLUDE_PATH="/opt/homebrew/opt/leveldb/include"
export LIBRARY_PATH="/opt/homebrew/opt/leveldb/lib"
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'

echo "LevelDB environment variables set:"
echo "  CPLUS_INCLUDE_PATH=${CPLUS_INCLUDE_PATH}"
echo "  LIBRARY_PATH=${LIBRARY_PATH}"
echo "  CXXFLAGS=${CXXFLAGS}"
