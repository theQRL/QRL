#!/bin/bash
echo "Killing python..."
/usr/bin/pkill python

echo "Updating QRL..."
cd $HOME/QRL
git pull

echo "Updating QRL pyhton dependencies..."
sudo pip install -r requirements.txt

echo "Restart QRL node"
python main.py

$SHELL
