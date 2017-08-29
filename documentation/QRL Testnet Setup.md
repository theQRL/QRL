QRL Testnet Setup Instructions
==============================

This document describes the setup procedure to install and configure a QRL node in the revived testnet on a Ubuntu host.


### Ensure your apt sources are up to date

`sudo apt update`

### Install python packages

- Ubuntu: `sudo apt-get install python-dev python-pip`
- CentOs: `sudo yum install python-devel python-pip`

### Clone the QRL Repo

`git clone https://github.com/theQRL/QRL.git`

### Change directory into the QRL Repo Folder

`cd QRL/`

### Install QRL Dependencies

`sudo pip install -r requirements.txt`

### Start your node

`qrl/main.py`


### Information

Your data and wallet will be stored in ${HOME}/.qrl

Testing PyPI packages (experimental)
====================================

We have experimental support for pip packages. You will not get a recent version and we recommend to stay with the git repo for a few more days. We will not be updating the pip package with every PR for now. Feedback is appreciated.

### Installing the qrl package:

`pip install -i https://testpypi.python.org/pypi --extra-index-url https://pypi.python.org/simple/  --upgrade qrl`

The command line is more complex because we are using testing repos. Once we release an stable version, things will get simpler.








