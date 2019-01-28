#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2012 thomasv@gitorious
#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from .uikit_bindings import *
from . import utils
from . import gui
from .custom_objc import *

from electroncash.i18n import _

import socket
from collections import namedtuple

from electroncash.network import serialize_server, deserialize_server

TAG_HELP_STATUS = 112
TAG_HELP_SERVER = 122
TAG_HELP_BLOCKCHAIN = 132
TAG_HELP_AUTOSERVER = 212
TAG_HOST_TF = 221
TAG_PORT_TF = 222
TAG_AUTOSERVER_SW = 210
TAG_SERVER_LBL = 121
TAG_STATUS_LBL = 111
TAG_HEIGHT_LBL = 131
TAG_SPLIT_LBL = 404
TAG_PEERS_TV = 240
TAG_CONNECTED_TV = 140

BUTTON_TAGS = (TAG_HELP_STATUS, TAG_HELP_SERVER, TAG_HELP_BLOCKCHAIN, TAG_HELP_AUTOSERVER)

ConnData = namedtuple("ConnData", "header items")

def parent() -> object:
    return gui.ElectrumGui.gui

class NetworkDialogVC(UIViewController):

    connectedTV = objc_property()
    untranslatedMap = objc_property()
    peersTV = objc_property()
    hostTF = objc_property()
    portTF = objc_property()
    autoServerSW = objc_property()
    serverLbl = objc_property()
    statusLbl = objc_property()
    heightLbl = objc_property()
    splitLbl = objc_property()
    splitAttrTxtOrig = objc_property()
    protocol = objc_property() # set to 't' for now -- TODO: figure out SSL stuff
    lastPort = objc_property()
    cellIdentifier = objc_property()
    kbas = objc_property()

    @objc_method
    def dealloc(self) -> None:
        parent().sigNetwork.disconnect(self)
        self.connectedTV = None
        self.untranslatedMap = None
        self.peersTV = None
        self.hostTF = None
        self.portTF = None
        self.autoServerSW = None
        self.serverLbl = None
        self.statusLbl = None
        self.heightLbl = None
        self.splitLbl = None
        self.splitAttrTxtOrig = None
        self.protocol = None
        self.lastPort = None
        self.cellIdentifier = None
        self.kbas = None
        utils.nspy_pop(self)
        send_super(__class__, self, 'dealloc')


    @objc_method
    def loadView(self) -> None:
        parent().sigNetwork.connect(lambda:self.refresh(), self)
        self.protocol = 't'
        self.cellIdentifier = "ServerPortCell22px"
        uinib = UINib.nibWithNibName_bundle_(self.cellIdentifier, None)
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("NetworkDialog",None,None)
        v = objs[0]
        sv = UIScrollView.alloc().initWithFrame_(CGRectMake(0,0,320,580)).autorelease()
        sv.contentSize = CGSizeMake(320,700)
        sv.addSubview_(v)

        self.connectedTV = v.viewWithTag_(TAG_CONNECTED_TV)
        self.connectedTV.registerNib_forCellReuseIdentifier_(uinib, self.cellIdentifier)
        self.connectedTV.dataSource = self
        self.connectedTV.delegate = self
        self.peersTV = v.viewWithTag_(TAG_PEERS_TV)
        self.peersTV.registerNib_forCellReuseIdentifier_(uinib, self.cellIdentifier)
        self.peersTV.dataSource = self
        self.peersTV.delegate = self

        self.view = sv

        self.lastPort = at(0)

        # connect buttons to functions
        views = self.view.allSubviewsRecursively()
        showHelpBlock = Block(showHelpForButton)
        def onAutoServerSW(oid : objc_id) -> None:
            self.doSetServer()
            self.refresh()
            self.updateAutoServerSWStuff()
        def onTfChg(oid : objc_id) -> None:
            tf = ObjCInstance(oid)
            print("tf %d changed txt = %s"%(int(tf.tag),str(tf.text)))
            if tf.tag == TAG_PORT_TF:
                try:
                    self.lastPort = int(tf.text)
                except ValueError:
                    self.lastPort = 0
                lastPort = str(py_from_ns(self.lastPort)) if self.lastPort else ''
                if lastPort != tf.text:
                    tf.text = lastPort

        onTfChgBlock = Block(onTfChg)
        for v in views:
            tag = v.tag
            if isinstance(v, UIButton) and tag in BUTTON_TAGS:
                v.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, showHelpBlock)
            elif isinstance(v, UISwitch) and tag is TAG_AUTOSERVER_SW:
                self.autoServerSW = v
                v.handleControlEvent_withBlock_(UIControlEventPrimaryActionTriggered, onAutoServerSW)
            elif isinstance(v, UITextField) and tag in (TAG_HOST_TF, TAG_PORT_TF):
                v.delegate = self
                if tag is TAG_HOST_TF: self.hostTF = v
                elif tag is TAG_PORT_TF: self.portTF = v
                v.handleControlEvent_withBlock_(UIControlEventEditingChanged,onTfChgBlock)
            # assign views we are interested in to our properties
            if tag == TAG_SERVER_LBL: self.serverLbl = v
            elif tag == TAG_STATUS_LBL: self.statusLbl = v
            elif tag == TAG_HEIGHT_LBL: self.heightLbl = v
            elif tag == TAG_SPLIT_LBL:
                self.splitLbl = v
                self.splitAttrTxtOrig = v.attributedText # cache original color, highlight, font, etc of text as defined in XIB as we'll need it later
        self.translateUI()

    @objc_method
    def translateUI(self) -> None:
        view = self.viewIfLoaded
        if view is None: return
        utmap = self.untranslatedMap
        if utmap is None: utmap = dict()
        def doTranslate(ns : ObjCInstance, txt_in : str) -> str:
            txt = utmap.get(ns.ptr.value, None)
            if txt is None:
                txt = txt_in
                utmap[ns.ptr.value] = txt
            txt = txt.strip()
            if not txt: return None
            hadColon = False
            if txt[-1] == ':':
                hadColon = True
                txt = txt[:len(txt)-1]
            return  _(txt) + (':' if hadColon else '')
        views = view.allSubviewsRecursively()
        for v in views:
            if isinstance(v, UILabel):
                txt = doTranslate(v, v.text)
                if txt: v.text = txt
            if isinstance(v, UITextField):
                txt = doTranslate(v, v.placeholder)
                if txt: v.placeholder = txt
        self.untranslatedMap = utmap

    @objc_method
    def updateAutoServerSWStuff(self) -> None:
        config = parent().config if parent() else None
        sw = self.autoServerSW
        if config is None or sw is None: return
        tags = [220, TAG_HOST_TF, TAG_PORT_TF, 230, TAG_PEERS_TV]
        enabled = False

        if config.is_modifiable('server'):
            enabled = not sw.isOn()
        else:
            tags += TAG_AUTOSERVER_SW
            enabled = False
        for t in tags:
            v = self.view.viewWithTag_(t)
            if v is None: continue
            utils.uiview_set_enabled(v, enabled)


    @objc_method
    def refresh(self) -> None:
        utils.NSLog("NETOWRK VC UPDATE, isMainThread = %s",str(NSThread.currentThread.isMainThread))
        if not parent() or not parent().daemon or not parent().daemon.network:
            utils.NSLog("NetworkDialogVC: No network defined, returning early from refresh")
            return
        if not parent().networkVC or not self.viewIfLoaded:
            utils.NSLog("NetworkDialogVC: Returning early, view has been deallocated")
            return
        network = parent().daemon.network
        chains = network.get_blockchains()
        n_chains = len(chains)
        host, port, protocol, proxy_config, auto_connect = network.get_parameters()
        self.hostTF.text = str(host)
        self.portTF.text = str(port)
        self.lastPort = at(int(port))
        self.autoServerSW.on = bool(auto_connect)

        host = network.interface.host if network.interface else _('None')
        self.serverLbl.text = str(host)

        #self.set_protocol(protocol)
        self.protocol = protocol
        servers_orig = network.get_servers()
        servers = []
        if servers_orig: servers_orig = sorted(servers_orig.items())
        use_tor = False
        for s in servers_orig:
            # filter out tor and servers with no port on our protocol
            host, d = s
            if host.endswith('.onion') and not use_tor:
                continue
            if d.get(protocol,None):
                ser_server = serialize_server(host, d.get(protocol), protocol)
                servers.append((host, d, ser_server))
        utils.nspy_put_byname(self, servers, 'servers')
        self.peersTV.reloadData()
        self.updateAutoServerSWStuff()

        height_str = "%d "%(network.get_local_height()) + _('blocks')
        self.heightLbl.text = str(height_str)
        n = len(network.get_interfaces())
        status = _("Connected to %d nodes.")%n if n else _("Not connected")
        self.statusLbl.text = str(status)
        if len(chains)>1:
            chain = network.blockchain()
            checkpoint = chain.get_base_height()
            name = chain.get_name()
            msg = _('Chain split detected at block %d')%checkpoint + '\n'
            msg += (_('You are following branch') if auto_connect else _('Your server is on branch'))+ ' ' + name
            msg += ' (%d %s)' % (chain.get_branch_size(), _('blocks'))
        else:
            msg = ''
        utils.uilabel_replace_attributed_text(self.splitLbl, msg, self.splitAttrTxtOrig)

        # setup 'connected' data -- list of ConnData items
        connected = []
        for k, items in chains.items():
            b = network.blockchains[k]
            name = b.get_name()
            secHeader = _("Connected node") + ", " + _("Height")
            secItems = list()
            extraData = None
            if n_chains > 1:
                secHeader = "(" + (name + '@%d'%b.get_base_height()) + ") " + _("Host") + ", " + _("Height")
                extraData = [ False, b.base_height, name ]
            for i in items:
                star = ' *' if i == network.interface else ''
                extraData = [True, i.server, ''] #if n_chains <= 1 else extraData
                item = [i.host + star, '%d'%i.tip, extraData]
                secItems.append(item)
            section = ConnData(secHeader,secItems)
            connected.append(section)
        utils.nspy_put_byname(self, connected, 'connected')

        self.connectedTV.reloadData()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__,self,'viewWillAppear:', c_bool(animated), argtypes=[c_bool])
        self.refresh()
        self.kbas = utils.register_keyboard_autoscroll(self.view)

    @objc_method
    def viewWillDisappear_(self, animated : bool) -> None:
        send_super(__class__,self,'viewWillDisappear:', c_bool(animated), argtypes=[c_bool])
        if self.kbas:
            utils.unregister_keyboard_autoscroll(int(self.kbas))
            self.kbas = None

    @objc_method
    def viewDidAppear_(self, animated : bool) -> None:
        send_super(__class__,self,'viewDidAppear:', c_bool(animated), argtypes=[c_bool])
        self.view.flashScrollIndicators()
        self.connectedTV.flashScrollIndicators()
        self.peersTV.flashScrollIndicators()

    @objc_method
    def numberOfSectionsInTableView_(self, tv) -> int:
        if tv.ptr == self.connectedTV.ptr:
            connected = utils.nspy_get_byname(self, 'connected')
            return len(connected) if connected else 1
        elif tv.ptr == self.peersTV.ptr:
            return 1
        return 0

    @objc_method
    def tableView_titleForHeaderInSection_(self, tv : ObjCInstance, section : int) -> ObjCInstance:
        if tv.ptr == self.connectedTV.ptr:
            connected = utils.nspy_get_byname(self, 'connected')
            if not connected:
                return _("Connected node") + ", " + _("Height")
            return connected[section].header
        elif tv.ptr == self.peersTV.ptr:
            return _("Host") + ", " + _("Port")
        print("*** WARNING *** tableView is unknown in tableView_titleForHeaderInSection_!!")
        return _("Unknown")

    @objc_method
    def tableView_numberOfRowsInSection_(self, tv : ObjCInstance, section : int) -> int:
        if tv.ptr == self.connectedTV.ptr:
            connected = utils.nspy_get_byname(self, 'connected')
            cdata = connected[section] if connected and len(connected) > section else None
            if cdata is None: return 0
            return len(cdata.items)
        elif tv.ptr == self.peersTV.ptr:
            servers = utils.nspy_get_byname(self, 'servers')
            return len(servers) if servers else 0
        return 0


    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        cell = None
        identifier = self.cellIdentifier
        if tv.ptr == self.connectedTV.ptr:
            cell = tv.dequeueReusableCellWithIdentifier_(identifier) # will always return a valid cell because we registered our nib in loadView
            l1 = cell.viewWithTag_(150)
            l2 = cell.viewWithTag_(160)

            connected = utils.nspy_get_byname(self, 'connected')
            cdata = connected[indexPath.section] if connected and len(connected) > indexPath.section else None
            if cdata is not None and len(cdata.items) > indexPath.row:
                item = cdata.items[indexPath.row]
                l1.text = item[0]
                l2.text = item[1]
            else:
                l1.text = _("Unknown")
                l2.text = _("Unknown")
            cell.contentView.backgroundColor = UIColor.clearColor if not indexPath.row % 2 else UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.03)
        elif tv.ptr == self.peersTV.ptr:
            cell = tv.dequeueReusableCellWithIdentifier_(identifier) # will always return a valid cell because we registered our nib in loadView
            l1 = cell.viewWithTag_(150)
            l2 = cell.viewWithTag_(160)

            servers = utils.nspy_get_byname(self, 'servers')
            host = _('Unknown')
            d = {'t':0,'s':0}
            if indexPath.row < len(servers):
                host, d, ser = servers[indexPath.row]
            l1.text = str(host)
            l2.text = str(d.get(self.protocol,None))
            cell.contentView.backgroundColor = UIColor.clearColor if not indexPath.row % 2 else UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.03)
        return cell

    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath) -> None:
        print("ACCESSORY TAPPED CALLED")
        pass

    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath) -> None:
        print("DID SELECT ROW CALLED FOR SECTION %s, ROW %s"%(str(indexPath.section),str(indexPath.row)))
        if tv.ptr == self.connectedTV.ptr:
            connected = utils.nspy_get_byname(self, 'connected')
            cdata = connected[indexPath.section] if connected and len(connected) > indexPath.section else None
            message = _("Unknown")
            title = _("Error")
            is_server = True
            extraData = None
            if cdata is not None and len(cdata.items) > indexPath.row:
                item = cdata.items[indexPath.row]
                extraData = item[2]
                is_server = extraData[0]
                server_or_branch = extraData[1]
                if is_server:
                    server, port, *bla = deserialize_server(server_or_branch)
                    message = _("Do you wish to use\n{}:{}\nas the wallet server?").format(str(server),str(port))
                    title = str(_("Use as server") + '?')
                else:
                    branch = server_or_branch
                    name = extraData[2]
                    title = str(_("Follow this branch") + '?')
                    message = str(_("Do you wish to follow the\n{}@{}\nbranch?").format(str(name),str(branch)))
                def wantsToChangeServerOrBranch() -> None:
                    if is_server:
                        self.followServer_(str(server_or_branch))
                    else:
                        self.followBranch_(int(server_or_branch))
                parent().question(message = message,
                                  title = title,
                                  yesno = True,
                                  onOk = wantsToChangeServerOrBranch)
            else:
                parent().show_error("An unknown error occurred.")
        elif tv.ptr == self.peersTV.ptr and indexPath.section == 0:
            servers = utils.nspy_get_byname(self, 'servers')
            srv = servers[indexPath.row] if servers is not None and len(servers) > indexPath.row else None
            if srv is not None:
                h, d, ser = srv
                server, port, *bla = deserialize_server(ser)
                message = _("Do you wish to use\n{}:{}\nas the blockchain server?").format(str(server),str(port))
                title = str(_("Use as server") + '?')
                def wantsToChangeServer() -> None:
                    self.setServer_(ser)
                parent().question(message = message,
                                  title = title,
                                  yesno = True,
                                  onOk = wantsToChangeServer)

        tv.deselectRowAtIndexPath_animated_(indexPath, True)

    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        #print("textFieldDidEndEditing", tf.tag, tf.text)
        self.doSetServer()
        return True

    @objc_method
    def textFieldShouldReturn_(self, tf: ObjCInstance) -> bool:
        #print("textFieldShouldReturn", tf.tag)
        tf.resignFirstResponder()
        return True

    @objc_method
    def followBranch_(self, index : int) -> None:
        network = parent().daemon.network if parent() and parent().daemon else None
        if network is None: return
        network.follow_chain(index)
        self.refresh()

    @objc_method
    def followServer_(self, server_in : ObjCInstance) -> None:
        network = parent().daemon.network if parent() and parent().daemon else None
        if network is None: return
        server = py_from_ns(server_in)
        network.switch_to_interface(server)
        host, port, protocol, proxy, auto_connect = network.get_parameters()
        host, port, protocol = deserialize_server(server)
        network.set_parameters(host, port, protocol, proxy, auto_connect)
        self.refresh()

    @objc_method
    def doSetServer(self) -> None:
        network = parent().daemon.network if parent() and parent().daemon else None
        if network is None: return
        host, port, protocol, proxy, auto_connect = network.get_parameters()
        host = str(self.hostTF.text)
        port = str(self.portTF.text)
        auto_connect = self.autoServerSW.isOn()
        network.set_parameters(host, port, protocol, proxy, auto_connect)

    @objc_method
    def setServer_(self, s : ObjCInstance) -> None:
        host, port, protocol = deserialize_server(py_from_ns(s))
        self.hostTF.text = str(host)
        self.portTF.text = str(port)
        self.lastPort = int(port)
        self.doSetServer()
        self.refresh()


def showHelpForButton(oid : objc_id) -> None:
    tag = int(ObjCInstance(oid).tag)
    msg = _("Unknown")
    if tag is TAG_HELP_STATUS:
        msg = ' '.join([
            _("Electron Cash connects to several nodes in order to download block headers and find out the longest blockchain."),
            _("This blockchain is used to verify the transactions sent by your transaction server.")
        ])
    elif tag is TAG_HELP_SERVER:
        msg = _("Electron Cash sends your wallet addresses to a single server, in order to receive your transaction history.")
    elif tag is TAG_HELP_BLOCKCHAIN:
        msg = _('This is the height of your local copy of the blockchain.')
    elif tag is TAG_HELP_AUTOSERVER:
        msg = ' '.join([
            _("If auto-connect is enabled, Electron Cash will always use a server that is on the longest blockchain."),
            _("If it is disabled, you have to choose a server you want to use. Electron Cash will warn you if your server is lagging.")
        ])
    msg = msg.replace("Electrum","Electron Cash")
    parent().show_message(msg, title = _("Information"))
