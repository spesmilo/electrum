#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import re
import pkgutil
import sys, os, time, json
import optparse
import platform
from decimal import Decimal

try:
    import ecdsa  
except ImportError:
    sys.exit("Error: python-ecdsa does not seem to be installed. Try 'sudo pip install ecdsa'")

try:
    import aes
except ImportError:
    sys.exit("Error: AES does not seem to be installed. Try 'sudo pip install slowaes'")


is_local = os.path.dirname(os.path.realpath(__file__)) == os.getcwd()
is_android = 'ANDROID_DATA' in os.environ

import __builtin__
__builtin__.use_local_modules = is_local or is_android

# load local module as electrum
if __builtin__.use_local_modules:
    import imp
    imp.load_module('electrum', *imp.find_module('lib'))
    imp.load_module('electrum_gui', *imp.find_module('gui'))

from electrum import *

# get password routine
def prompt_password(prompt, confirm=True):
    import getpass
    if sys.stdin.isatty():
        password = getpass.getpass(prompt)
        if password and confirm:
            password2 = getpass.getpass("Confirm: ")
            if password != password2:
                sys.exit("Error: Passwords do not match.")
    else:
        password = raw_input(prompt)
    if not password:
        password = None
    return password

def arg_parser():
    usage = "%prog [options] command" 
    parser = optparse.OptionParser(prog=usage)
    parser.add_option("-g", "--gui", dest="gui", help="User interface: qt, lite, gtk or text")
    parser.add_option("-w", "--wallet", dest="wallet_path", help="wallet path (default: electrum.dat)")
    parser.add_option("-o", "--offline", action="store_true", dest="offline", default=False, help="remain offline")
    parser.add_option("-a", "--all", action="store_true", dest="show_all", default=False, help="show all addresses")
    parser.add_option("-b", "--balance", action="store_true", dest="show_balance", default=False, help="show the balance of listed addresses")
    parser.add_option("-l", "--labels", action="store_true", dest="show_labels", default=False, help="show the labels of listed addresses")
    parser.add_option("-f", "--fee", dest="tx_fee", default=None, help="set tx fee")
    parser.add_option("-F", "--fromaddr", dest="from_addr", default=None, help="set source address for payto/mktx. if it isn't in the wallet, it will ask for the private key unless supplied in the format public_key:private_key. It's not saved in the wallet.")
    parser.add_option("-c", "--changeaddr", dest="change_addr", default=None, help="set the change address for payto/mktx. default is a spare address, or the source address if it's not in the wallet")
    parser.add_option("-s", "--server", dest="server", default=None, help="set server host:port:protocol, where protocol is t or h")
    parser.add_option("-p", "--proxy", dest="proxy", default=None, help="set proxy [type:]host[:port], where type is socks4,socks5 or http")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="show debugging information")
    parser.add_option("-P", "--portable", action="store_true", dest="portable", default=False, help="portable wallet")
    parser.add_option("-L", "--lang", dest="language", default=None, help="defaut language used in GUI")
    parser.add_option("-u", "--usb", dest="bitkey", action="store_true", help="Turn on support for hardware wallets (EXPERIMENTAL)")
    return parser


if __name__ == '__main__':

    parser = arg_parser()
    options, args = parser.parse_args()
    if options.portable and options.wallet_path is None:
        options.wallet_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'electrum.dat')
    set_verbosity(options.verbose)

    # config is an object passed to the various constructors (wallet, interface, gui)
    if is_android:
        config_options = {'wallet_path':"/sdcard/electrum.dat", 'portable':True, 'verbose':True, 'gui':'android', 'auto_cycle':True}
    else:
        config_options = eval(str(options))
        for k, v in config_options.items():
            if v is None: config_options.pop(k)

    # Wallet migration on Electrum 1.7
    # Todo: In time we could remove this again
    if platform.system() == "Windows":
        util.check_windows_wallet_migration()

    config = SimpleConfig(config_options)
    wallet = Wallet(config)


    if len(args)==0:
        url = None
        cmd = 'gui'
    elif len(args)==1 and re.match('^bitcoin:', args[0]):
        url = args[0]
        cmd = 'gui'
    else:
        cmd = args[0]
       

    if cmd == 'gui':
        gui_name = config.get('gui','classic')
        try:
            gui = __import__('electrum_gui.gui_' + gui_name, fromlist=['electrum_gui'])
        except ImportError:
            sys.exit("Error: Unknown GUI: " + gui_name )
        
        interface = Interface(config, True)
        wallet.interface = interface

        gui = gui.ElectrumGui(wallet, config)

        found = config.wallet_file_exists
        if not found:
            a = gui.restore_or_create()
            if not a: exit()

            if a =='create':
                wallet.init_seed(None)
                gui.show_seed()
                if gui.verify_seed():
                    wallet.save_seed()
                else:
                    exit()

            else:
                # ask for seed and gap.
                sg = gui.seed_dialog()
                if not sg: exit()
                seed, gap = sg
                if not seed: exit()
                wallet.gap_limit = gap
                if len(seed) == 128:
                    wallet.seed = ''
                    wallet.init_sequence(str(seed))
                else:
                    wallet.init_seed(str(seed))
                    wallet.save_seed()
            
            # select a server.
            s = gui.network_dialog()
            if s is None:
                config.set_key("server", None, True)
                config.set_key('auto_cycle', False, True)
            
        interface.start(wait = False)
        interface.send([('server.peers.subscribe',[])])

        # generate the first addresses, in case we are offline
        if not found and ( s is None or a == 'create'):
            wallet.synchronize()

        verifier = WalletVerifier(interface, config)
        verifier.start()
        wallet.set_verifier(verifier)
        synchronizer = WalletSynchronizer(wallet, config)
        synchronizer.start()

        if not found and a == 'restore' and s is not None:
            try:
                keep_it = gui.restore_wallet()
                wallet.fill_addressbook()
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                exit()

            if not keep_it: exit()

        if not found:
            gui.password_dialog()

        #wallet.save()
        gui.main(url)
        #wallet.save()

        verifier.stop()
        synchronizer.stop()
        interface.stop()

        # we use daemon threads, their termination is enforced.
        # this sleep command gives them time to terminate cleanly. 
        time.sleep(0.1)
        sys.exit(0)

    if cmd not in known_commands:
        cmd = 'help'

    if not config.wallet_file_exists and cmd not in ['help','create','restore']:
        print_msg("Error: Wallet file not found.")
        print_msg("Type 'electrum create' to create a new wallet, or provide a path to a wallet with the -w option")
        sys.exit(0)
    
    if cmd in ['create', 'restore']:
        if config.wallet_file_exists:
            sys.exit("Error: Remove the existing wallet first!")
        password = prompt_password("Password (hit return if you do not wish to encrypt your wallet):")

        server = config.get('server')
        if not server: server = pick_random_server()
        w_host, w_port, w_protocol = server.split(':')
        host = raw_input("server (default:%s):"%w_host)
        port = raw_input("port (default:%s):"%w_port)
        protocol = raw_input("protocol [t=tcp;h=http] (default:%s):"%w_protocol)
        fee = raw_input("fee (default:%s):"%( str(Decimal(wallet.fee)/100000000)) )
        gap = raw_input("gap limit (default 5):")
        if host: w_host = host
        if port: w_port = port
        if protocol: w_protocol = protocol
        wallet.config.set_key('server', w_host + ':' + w_port + ':' +w_protocol)
        if fee: wallet.fee = float(fee)
        if gap: wallet.gap_limit = int(gap)

        if cmd == 'restore':
            seed = raw_input("seed:")
            try:
                seed.decode('hex')
            except:
                print_error("Warning: Not hex, trying decode.")
                seed = mnemonic_decode( seed.split(' ') )
            if not seed:
                sys.exit("Error: No seed")

            if len(seed) == 128:
                wallet.seed = None
                wallet.init_sequence(str(seed))
            else:
                wallet.init_seed( str(seed) )
                wallet.save_seed()

            interface = Interface(config)
            if not options.offline:
                if not interface.start(wait=True):
                    print_msg("Not connected, aborting. Try option -o if you want to restore offline.")
                    sys.exit(1)
                wallet.interface = interface
                verifier = WalletVerifier(interface, config)
                verifier.start()
                wallet.set_verifier(verifier)

                print_msg("Recovering wallet...")
                WalletSynchronizer(wallet, config).start()
                wallet.update()
                if wallet.is_found():
                    print_msg("Recovery successful")
                else:
                    print_msg("Warning: Found no history for this wallet")
            else:
                interface.start(wait=False)
                wallet.synchronize()
            wallet.fill_addressbook()
            #wallet.save()
            print_msg("Wallet saved in '%s'"%wallet.config.path)
        else:
            wallet.init_seed(None)
            wallet.save_seed()
            wallet.synchronize() # there is no wallet thread 
            print_msg("Your wallet generation seed is: " + wallet.seed)
            print_msg("Please keep it in a safe place; if you lose it, you will not be able to restore your wallet.")
            print_msg("Equivalently, your wallet seed can be stored and recovered with the following mnemonic code:")
            print_msg("\""+' '.join(mnemonic_encode(wallet.seed))+"\"")
            print_msg("Wallet saved in '%s'"%wallet.config.path)
            
        if password:
            wallet.update_password(wallet.seed, None, password)

        # terminate
        sys.exit(0)



    # important warning
    if cmd in ['dumpprivkey', 'dumpprivkeys']:
        print_msg("WARNING: ALL your private keys are secret.")
        print_msg("Exposing a single private key can compromise your entire wallet!")
        print_msg("In particular, DO NOT use 'redeem private key' services proposed by third parties.")

    # commands needing password
    if cmd in protected_commands:
        if wallet.use_encryption:
            password = prompt_password('Password:', False)
            if not password:
                print_msg("Error: Password required")
                exit(1)
            # check password
            try:
                seed = wallet.decode_seed(password)
            except:
                print_msg("Error: This password does not decode this wallet.")
                exit(1)
        else:
            password = None
            seed = wallet.seed
    else:
        password = None


    # add missing arguments, do type conversions
    if cmd == 'importprivkey':
        # See if they specificed a key on the cmd line, if not prompt
        if len(args) == 1:
            args[1] = prompt_password('Enter PrivateKey (will not echo):', False)

    elif cmd == 'signrawtransaction':
        args = [ cmd, args[1], json.loads(args[2]) if len(args)>2 else [], json.loads(args[3]) if len(args)>3 else []]

    elif cmd == 'createmultisig':
        args = [ cmd, int(args[1]), json.loads(args[2])]

    elif cmd == 'createrawtransaction':
        args = [ cmd, json.loads(args[1]), json.loads(args[2])]

    elif cmd == 'listaddresses':
        args = [cmd, options.show_all, options.show_balance, options.show_labels]

    elif cmd in ['payto', 'mktx']:
        domain = [options.from_addr] if options.from_addr else None
        args = [ 'mktx', args[1], Decimal(args[2]), Decimal(options.tx_fee) if options.tx_fee else None, options.change_addr, domain ]

    elif cmd == 'help':
        if len(args) < 2:
            parser.print_help()
            print_msg("Type 'electrum help <command>' to see the help for a specific command")
            print_msg("Type 'electrum --help' to see the list of options")


                

    # check the number of arguments
    min_args, max_args, description, syntax, options_syntax = known_commands[cmd]
    if len(args) - 1 < min_args:
        print_msg("Not enough arguments")
        print_msg("Syntax:", syntax)
        sys.exit(1)

    if max_args >= 0 and len(args) - 1 > max_args:
        print_msg("too many arguments", args)
        print_msg("Syntax:", syntax)
        sys.exit(1)

    if max_args < 0:
        if len(args) > min_args + 1:
            message = ' '.join(args[min_args:])
            print_msg("Warning: Final argument was reconstructed from several arguments:", repr(message))
            args = args[0:min_args] + [ message ]
        




    # open session
    if cmd not in offline_commands and not options.offline:
        interface = Interface(config)
        interface.register_callback('connected', lambda: sys.stderr.write("Connected to " + interface.connection_msg + "\n"))
        if not interface.start(wait=True):
            print_msg("Not connected, aborting.")
            sys.exit(1)
        wallet.interface = interface
        verifier = WalletVerifier(interface, config)
        verifier.start()
        wallet.set_verifier(verifier)
        synchronizer = WalletSynchronizer(wallet, config)
        synchronizer.start()
        wallet.update()
        #wallet.save()


    # run the command

    if cmd == 'deseed':
        if not wallet.seed:
            print_msg("Error: This wallet has no seed")
        else:
            ns = wallet.config.path + '.seedless'
            print_msg("Warning: you are going to create a seedless wallet'\nIt will be saved in '%s'"%ns)
            if raw_input("Are you sure you want to continue? (y/n) ") in ['y','Y','yes']:
                wallet.config.path = ns
                wallet.seed = ''
                wallet.config.set_key('seed', '', True)
                wallet.use_encryption = False
                wallet.config.set_key('use_encryption', wallet.use_encryption, True)
                for k in wallet.imported_keys.keys(): wallet.imported_keys[k] = ''
                wallet.config.set_key('imported_keys',wallet.imported_keys, True)
                print_msg("Done.")
            else:
                print_msg("Action canceled.")

    elif cmd == 'getconfig':
        key = args[1]
        print_msg(wallet.config.get(key))

    elif cmd == 'setconfig':
        key, value = args[1:3]
        if key not in ['seed', 'seed_version', 'master_public_key', 'use_encryption']:
            wallet.config.set_key(key, value, True)
            print_msg(True)
        else:
            print_msg(False)

    elif cmd == 'password':
        new_password = prompt_password('New password:')
        wallet.update_password(seed, password, new_password)

    else:
        cmd_runner = Commands(wallet, interface)
        func = eval('cmd_runner.' + cmd)
        cmd_runner.password = password
        try:
            result = func(*args[1:])
        except BaseException, e:
            print_msg("Error: " + str(e))
            sys.exit(1)
            
        if type(result) == str:
            util.print_msg(result)
        elif result is not None:
            util.print_json(result)
            
        

    if cmd not in offline_commands and not options.offline:
        verifier.stop()
        synchronizer.stop()
        interface.stop()
        time.sleep(0.1)
        sys.exit(0)
