# Running a Quantum Resistant Ledger node on a Raspberry Pi

## Raspberry Pi operating system installation & setup : 

- Download latest Raspberry Pi operating system image : https://www.raspberrypi.org/downloads/raspbian/
- Install it using official Raspberry instructions :https://www.raspberrypi.org/documentation/installation/installing-images/README.md
- Change default pi password by opening a terminal and type the following command :

```passwd ```  
> default password is 'raspberry'. Enter a new password (twice)

- General setup to set locale, Time Zone, Hostname, in Adv Menu Expand Filesystem to match uSD). For more detail see : https://www.raspberrypi.org/documentation/configuration/raspi-config.md

```	sudo raspi-config ``` 

    
- If required, edit the network config file to set up a static IP address. For more details see : https://raspberrypi.stackexchange.com/questions/37920/how-do-i-set-up-networking-wifi-static-ip-address

```sudo nano /etc/network/interfaces``` 

        
- Get last updates :

```sudo apt update```

- Install firewall
```
sudo apt-get install ufw
```

- Setup firewall rules
```
sudo ufw allow OpenSSH
sudo ufw allow 9000/tcp
sudo ufw allow from 127.0.0.1 to 127.0.0.1 port 2000 proto tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing 
sudo ufw enable
```

- Check firewall status

```
sudo ufw status verbose
```

## QRL installation & Running the node
- Install dependencies :

```
sudo apt -y install swig3.0 python3-dev build-essential cmake ninja-build libboost-random-dev libssl-dev libffi-dev
sudo pip3 install -U setuptools
```

- To get the source and start the node, use the following: :

```
pip3 install --user -U qrl
start_qrl
```

- If you've set it up correctly, it should start to output the following:
```
|unsynced| INFO : Data Path: /home/pi/.qrl/data
|unsynced| INFO : Wallet Path: /home/pi/.qrl/wallet
|unsynced| INFO : Initializing chain..
|unsynced| INFO : DB path: /home/pi/.qrl/data/state
|unsynced| INFO : Creating new wallet file... (this could take up to a minute)
```
After the wallet is created it will start synchronizing the chain.
This might take a while, leave it running until the chain is sync

- If you want to keep QRL running after disconnecting terminal, you have to launch it in background :

```nohup start_qrl &```

- By default nohup will output logs to ${CWD}/nohup.out. Override this with

```nohup start_qrl > /path/to/file.log &

## Check Sync process

- You can find the status of the sync process (synced, syncing or unsynced) in the QRL log :

```grep -i sync /path/to/file.log | tail -1```

- Find last received blocks and compare it with QRL chain explorer http://qrlexplorer.info/

```grep -i "Received Block" /path/to/file.log | tail -1```

> Another way to get the last received block is to connect locally on the wallet (see below) and use command `blockheight`



## Check QRL memory usage

- Find QRL process :

```pgrep start_qrl```

- Check memory usage

```top -p <python process id>```

- Is this example, memory usage is : 112MB (994232 x 11.2%)

```
pi@raspberrypi:$ pgrep start_qrl
5051
pi@raspberrypi:$ top -p 5051
top - 21:42:59 up 11 days, 17 min,  3 users,  load average: 1.54, 1.43, 0.99
Tasks:   1 total,   1 running,   0 sleeping,   0 stopped,   0 zombie
%Cpu(s): 32.6 us,  2.0 sy,  0.0 ni, 49.6 id, 15.9 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem :   **994232** total,   183584 free,   239048 used,   571600 buff/cache
KiB Swap:   524284 total,   482864 free,    41420 used.   625072 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 5051 pi        20   0  129784 111256  11264 R 135.7 **11.2**  15:18.28 start_qrl
```


## Stopping the node
- It can be required to stop the node, specially during testnet. Type the following to kill python process.

```pkill start_qrl```

## Update the node

- First stop the python process (see above) and update the package through pip

```
pip3 install --user -U qrl
```
- restart QRL

```
start_qrl
```

## Accessing the wallet
- To access the wallet, you need telnet. Type the following command to install telnet :

`sudo apt-get install telnet`

- Run the following command to start the node :

`start_qrl`

- Once it starts the synchronisation process, you can telnet into the node. Type the following command in the terminal :

`telnet localhost 2000`

> type `help` for the cmd list

## Launch the node automatically at startup
- In the system settings (Start - Preferences - Raspberry Pi Configuration), make sure the "Boot" option is set to "To Desktop". In GUI distributions this is already pre-configured.

- Add the script to the autostart folder (the location of the autostart file varies depending on your raspberry distribution) :

`nano /home/pi/.config/lxsession/LXDE-pi/autostart`

- Add the following line above(!) @xscreensaver -no-splash :

`@lxterminal -e start_qrl &`
Press ctrl+x to close, press y to save and press enter

- See if it works!

## Launch the node automatically every night
- It can be useful to restart the node on a regular basis, specially during testnet

- Edit the crontab to restart QRL automatically

`crontab -e`

- Append the following entry :

`43 6 * * * pkill start_qrl && start_qrl`

> In this example, QRL is restarted every day at 6:43. Please change the time to whatever in order to avoid all nodes restart at same time !
