# Running a Quantum Resistant Ledger node on a Raspberry Pi

## Getting setup
* Download an image for your raspberry pi and write it to your micro sd card.
* Power up your raspberry pi

> Tested working for 2017-03-02-raspbian-jessie and 2016-11-25-raspbian-jessie (these images come with pip, git and python 2.7 included). Image building on windows can be done using Win32 Disk Imager.
## Downloading the necessary dependencies 
Open a terminal (crtl+alt+t) and type the following commands:
```
sudo apt-get install python-dev
sudo pip install jsonpickle
sudo pip install leveldb
sudo pip install Twisted==16.0.0
sudo pip install blessings
sudo pip install statistics
```

## Cloning the Quantum Resistant Ledger source code
Type the following command to clone the repository:
`git clone https://github.com/theQRL/QRL.git`

## Running the node
In the terminal, type the following commands:

```
cd QRL
python node.py
```
If you've set it up correctly, it should start to output the following:

```
loading db
loading wallet
Creating new wallet file..this could take up to a minute

After the wallet is created it will start syncronizing the chain.
This might take a while, leave it running untill the chain is sync
```

## Accessing the wallet
To acces the wallet, you need telnet. Install telnet:
`sudo apt-get install telnet`

Run the following command to start the node:
`python node.py`

Once it starts the synchronisation process, you can telnet into the node. Type the following command in the terminal:
`telnet localhost 2000`

> type `help` for the cmd list

## Launch the node automatically at startup
In the system settings (Start - Preferences - Raspberry Pi Configuration), make sure the "Boot" option is set to "To Desktop". In GUI distributions this is already pre-configured.

Open up a terminal and create a new script called `autostartQRL.sh`:
`sudo nano autostartQRL.sh`

Type in the following lines in `autostartQRL.sh`:

```
#!/bin/bash
cd /home/pi/QRL (or cd /location/QRL source code folder)
python node.py
$SHELL (to keep the terminal open)
```

Press ctrl+x to close, press y to save and press enter

Make the sh script executable:
`chmod +x autostartQRL.sh`

Add the script to the autostart folder (the location of the autostart file varies depending on your raspberry distribution):
`nano /home/pi/.config/lxsession/LXDE-pi/autostart`

Add the following line above(!) @xscreensaver -no-splash:
`@lxterminal -e /home/pi/autostartQRL.sh &`

Press ctrl+x to close, press y to save and press enter

Make the python script executable:
`sudo chmod +x [your folder]/QRL/node.py`

See if it works!
