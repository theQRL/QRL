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

`pip install -r requirements.txt`

### Start your node

`python main.py`

