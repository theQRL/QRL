#!/usr/bin/env
#-*- coindg:utf-8 -*-

import pdb
import time
import telnetlib

from cmd import Cmd

try:
    import readline
    if "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
except:
    pass


class BaseInterpreter(Cmd):
    def __init__(self, host="127.0.0.1", port=2000):
        Cmd.__init__(self)

        self.prompt = "QRL> "
        self.case_insentive = False

        self.tel = telnetlib.Telnet(host, port, timeout=5)
        self.tel.read_until("\r\n")

    def response(self):
        time.sleep(1)
        msg = self.tel.read_very_eager()
        print(msg)
            

    def do_wallet(self, line):
        self.tel.write("wallet")
        self.response()

    def do_send(self, line):
        self.tel.write("send " + line)
        self.response()

    def do_getnewaddress(self, line):
        self.tel.write("getnewaddress " + line)
        self.response()

    def do_search(self, line):
        self.tel.write("search " + line)
        self.response()

    def do_recoverfromhexseed(self, line):
        self.tel.write("recoverfromhexseed " + line)
        self.response()

    def do_recoverfromwords(self, line):
        self.tel.write("recoverfromwords " + line)
        self.response()

    def do_stake(self, line):
        self.tel.write("stake " + line)
        self.response()

    def do_stakenextepoch(self, line):
        self.tel.write("stakenextepoch " + line)
        self.response()

    def do_mempool(self, line):
        self.tel.write("mempool " + line)
        self.response()

    def do_json_block(self, line):
        self.tel.write("json_block " + line)
        self.response()

    def do_json_search(self, line):
        self.tel.write("json_search " + line)
        self.response()

    def do_seed(self, line):
        self.tel.write("seed " + line)
        self.response()

    def do_hexseed(self, line):
        self.tel.write("hexseed " + line)
        self.response()

    def do_getinfo(self, line):
        self.tel.write("getinfo " + line)
        self.response()

    def do_peers(self, line):
        self.tel.write("peers " + line)
        self.response()

    def do_blockheight(self, line):
        self.tel.write("blockheight " + line)
        self.response()


if __name__ == "__main__":
    b = BaseInterpreter()

    try:
        b.cmdloop()
    except (KeyboardInterrupt, pdb.bdb.BdbQuit):
        print("quit")

    b.tel.close()
