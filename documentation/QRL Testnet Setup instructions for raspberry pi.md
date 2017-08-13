# Running a Quantum Resistant Ledger node on a Raspberry Pi

## Raspberry Pi operating system installation & setup : 

- Download latest Raspberry Pi operating system image : https://www.raspberrypi.org/downloads/raspbian/
- Install it using official Raspberry instructions :https://www.raspberrypi.org/documentation/installation/installing-images/README.md
- Change default pi password by openning a terminal and type the following command :

```passwd ```  
> default password is 'raspberry'. Enter a new password (twice)

- General setup to set locale, Time Zone, Hostname, in Adv Menu Expand Filesystem to match uSD). For more detail see : https://www.raspberrypi.org/documentation/configuration/raspi-config.md

```	sudo raspi-config ``` 

	
- If required, edit the network config file to set up a static IP address. For more details see : https://raspberrypi.stackexchange.com/questions/37920/how-do-i-set-up-networking-wifi-static-ip-address

```sudo nano /etc/network/interfaces``` 

		
- Get last updates :

```sudo apt update```

## QRL installation & setup
- Install python packages :

```sudo apt-get install python-dev```

- Install dependencies :

```sudo pip install -r requirements.txt```
  
- Type the following command to clone the repository :

```git clone https://github.com/theQRL/QRL.git```
  
## Running the node
- In the terminal, type the following commands :
```
cd QRL
python main.py
```

- If you've set it up correctly, it should start to output the following:
```
Creating new wallet file..this could take up to a minute
QRL blockchain ledger  alpha/0.xx
loading db
loading wallet
Error: likely no wallet.info found, creating..
Fast saving wallet recovery details to wallet.info..
```
After the wallet is created it will start syncronizing the chain.
This might take a while, leave it running untill the chain is sync

- If you want to keep QRL running after disconnecting terminal, you have to launch it in background :

```nohup python main.py > /dev/null 2>&1 &```

## Stopping the node
- It can be required to stop the node, specialy during testnet. Type the following to kill python process.

```pkill python```

## Accessing the wallet
- To acces the wallet, you need telnet. Type the following command to install telnet :

`sudo apt-get install telnet`

- Run the following command to start the node :

`python main.py`

- Once it starts the synchronisation process, you can telnet into the node. Type the following command in the terminal :

`telnet localhost 2000`

> type `help` for the cmd list

## Launch the node automatically at startup
- In the system settings (Start - Preferences - Raspberry Pi Configuration), make sure the "Boot" option is set to "To Desktop". In GUI distributions this is already pre-configured.

- Create a new script (for example autostartQRL.sh) :

`nano /home/pi/autostartQRL.sh`

- Type in the following lines in the script `autostartQRL.sh`:

```
#!/bin/bash
cd /home/pi/QRL (or cd /location/QRL source code folder)
python main.py
$SHELL (to keep the terminal open)
```
Press ctrl+x to close, press y to save and press enter

- Make the sh script executable :

`chmodx autostartQRL.sh`

- Add the script to the autostart folder (the location of the autostart file varies depending on your raspberry distribution) :

`nano /home/pi/.config/lxsession/LXDE-pi/autostart`

- Add the following line above(!) @xscreensaver -no-splash :

`@lxterminal -e /home/pi/autostartQRL.sh &`
Press ctrl+x to close, press y to save and press enter

- Make the python script executable :

`sudo chmodx [your folder]/QRL/main.py`

- See if it works!
