#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from electroncash import WalletStorage, Wallet
from electroncash.address import Address, PublicKey
from electroncash.util import timestamp_to_datetime, PrintError, profiler
from electroncash.i18n import _, language

import time, math, sys, os
from collections import namedtuple

from .uikit_bindings import *
from .custom_objc import *

HistoryEntry = namedtuple("HistoryEntry", "tx tx_hash status_str label v_str balance_str date ts conf status value fiat_amount fiat_balance fiat_amount_str fiat_balance_str ccy status_image")
#######################################################################
# HELPER STUFF EXPORTED TO OTHER MODULES ('Addresses' uses these too) #
#######################################################################
StatusImages = [  # Indexed by 'status' from tx info and/or HistoryEntry
    UIImage.imageNamed_("warning.png").retain(),
    UIImage.imageNamed_("warning.png").retain(),
    UIImage.imageNamed_("unconfirmed.png").retain(),
    UIImage.imageNamed_("unconfirmed.png").retain(),
    UIImage.imageNamed_("clock1.png").retain(),
    UIImage.imageNamed_("clock2.png").retain(),
    UIImage.imageNamed_("clock3.png").retain(),
    UIImage.imageNamed_("clock4.png").retain(),
    UIImage.imageNamed_("clock5.png").retain(),
    UIImage.imageNamed_("grnchk.png").retain(),
    UIImage.imageNamed_("signed.png").retain(),
    UIImage.imageNamed_("unsigned.png").retain(),
]

class _HistoryListProxy:
    '''
        This class mimics a python list, and may be returned from HistoryMgr.doReloadForKey
        (in some cases an actual list is returned from that method, though).

        This class implements on-demand creation of HistoryEntry entries as they are accessed.

        The rationale behind this class's mechanism is as a performance speedup since iOS allows us
        to load tableView cells on-demand anyway, so there's no sense in pre-populating all the history
        data ahead of time on app gui.refresh_all(), as it may never get seen on-screen anyway.
    '''
    def __init__(self, statusImagesOverride=None, forceNoFX=False):
        self.statusImagesOverride = statusImagesOverride
        self.forceNoFX = forceNoFX
        self.hentries = dict() # index in self.hitems -> HistoryEntry named tuple
        self.hitems = list() # list of tuples as returned by wallet.get_history()
        self.txids = dict() # map of txid (tx_hash) -> index
    def set_hitems(self,hitems):
        self.hentries = dict()
        self.txids = dict()
        self.hitems = hitems if hitems else list()
    def get_by_txid(self, txid):
        index = self.txids.get(txid)
        if index is None:
            for i,hitem in enumerate(self.hitems):
                if hitem[0] == txid:
                    index = i
                    self.txids[txid] = index
                    break
        if index is not None:
            return self[index]
        else:
            raise KeyError('cannot find txid %s in hitems'%txid)
    def __len__(self):
        return len(self.hitems)
    def __bool__(self):
        return bool(self.hitems)
    def __iter__(self):
        class Iter:
            def __init__(self, hlp):
                self.hlp = hlp
                self.i = 0
            def __next__(self):
                if self.i < len(self.hlp):
                    self.i += 1
                    return self.hlp[self.i-1]
                else:
                    raise StopIteration
        return Iter(self)
    def __getitem__(self,index):
        if index < 0:
            index += len(self)
        if index >= len(self) or index < 0:
            raise IndexError('_HistoryListProxy index out of range')
        he = self.hentries.get(index)
        if he is None:
            hitem = self.hitems[index]
            he = _HistoryListProxy._build_history_entry(hitem, self.statusImagesOverride, self.forceNoFX) # populate the HistoryEntry if it was missing
            self.hentries[index] = he # save HistoryEntry
        self.txids[he.tx_hash] = index # remember the index for this txid
        return he
    def __setitem__(self,index,val):
        if index < 0:
            index += len(self)
        if index >= len(self) or index < 0:
            raise IndexError('_HistoryListProxy index out of range')
        if not isinstance(val, HistoryEntry):
            raise ValueError('Can only add objects of type HistoryEntry to this list')
        self.hentries[index] = val
        self.txids[val.tx_hash] = index # rememebr the index for this txid
        return val
    def append(self,hentry):
        self.hitems.append(None) # null hitem is ok here, because if hentry exists for a particular index, hitems are ignored anyway
        ln = len(self.hentries)
        self[ln-1] = hentry
        NSLog("_HistoryListProxy.append() called -- this isn't really supported. FIXME!")
    def __contains__(self,hentry):
        if not isinstance(hentry,HistoryEntry):
            return False
        index = self.txids.get(hentry.tx_hash)
        if index is not None:
            return True
        for i,hitem in enumerate(self.hitems):
            if hitem[0] == hentry.tx_hash:
                self.txids[hentry.tx_hash] = i
                if i not in self.hentries: self.hentries[i] = hentry
                return True
        return False

    @staticmethod
    def _build_history_entry(h_item, statusImagesOverride, forceNoFX):
        sImages = StatusImages if not statusImagesOverride or len(statusImagesOverride) < len(StatusImages) else statusImagesOverride
        parent = gui.ElectrumGui.gui
        wallet = parent.wallet
        daemon = parent.daemon
        if wallet is None or daemon is None:
            utils.NSLog("buid_history_entry: wallet and/or daemon was None, returning early")
            return None
        fx = daemon.fx if daemon.fx and daemon.fx.show_history() else None
        ccy = ''
        tx_hash, height, conf, timestamp, value, balance = h_item
        status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)
        has_invoice = wallet.invoices.paid.get(tx_hash)
        v_str = parent.format_amount(value, True, whitespaces=True)
        balance_str = parent.format_amount(balance, whitespaces=True)
        label = wallet.get_label(tx_hash)
        date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
        ts = timestamp if conf > 0 else time.time()
        fiat_amount = 0
        fiat_balance = 0
        fiat_amount_str = ''
        fiat_balance_str = ''
        if fx: fx.history_used_spot = False
        if not forceNoFX and fx:
            if not ccy:
                ccy = fx.get_currency()
            try:
                hdate = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                hamount = fx.historical_value(value, hdate)
                htext = fx.historical_value_str(value, hdate) if hamount else ''
                fiat_amount = hamount if hamount else fiat_amount
                fiat_amount_str = htext if htext else fiat_amount_str
                hamount = fx.historical_value(balance, hdate) if balance else 0
                htext = fx.historical_value_str(balance, hdate) if hamount else ''
                fiat_balance = hamount if hamount else fiat_balance
                fiat_balance_str = htext if htext else fiat_balance_str
            except:
                utils.NSLog("Exception in get_history computing fiat amounts!\n%s",str(sys.exc_info()[1]))
                #import traceback
                #traceback.print_exc(file=sys.stderr)
                fiat_amount = fiat_balance = 0
                fiat_amount_str = fiat_balance_str = ''
        if status >= 0 and status < len(sImages):
            img = sImages[status]
        else:
            img = None
        tx = wallet.transactions.get(tx_hash, None)
        if tx is not None: tx.deserialize()
        entry = HistoryEntry(tx, tx_hash, status_str, label, v_str, balance_str, date, ts, conf, status, value, fiat_amount, fiat_balance, fiat_amount_str, fiat_balance_str, ccy, img)
        return entry

def get_history(domain : list = None, statusImagesOverride : list = None, forceNoFX : bool = False) -> object:
    ''' For a given set of addresses (or None for all addresses), builds a list of
        HistoryEntry '''
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    daemon = parent.daemon
    ret = _HistoryListProxy(statusImagesOverride, forceNoFX)
    if wallet is None or daemon is None:
        utils.NSLog("get_history: wallet and/or daemon was None, returning early")
        return ret
    h = wallet.get_history(domain)
    h.reverse()
    ret.set_hitems(h)
    return ret

from . import txdetail
from . import contacts
from typing import Any

class HistoryMgr(utils.DataMgr):
    def doReloadForKey(self, key : Any) -> Any:
        t0 = time.time()
        hist = list()
        unk = False
        duped = ''
        if isinstance(key, (type(None), list)):
            # the common case, 'None' or [Address]
            hist = get_history(domain = key)
        # contacts entires
        elif isinstance(key, contacts.ContactsEntry):
            hist = get_contact_history(key.address)
        elif isinstance(key, Address):
            # support for list-less single Address.. call self again with the proper format
            hist = self.get([key])
            duped = ' (duped) '
        elif isinstance(key, str):
            # support for string addresses or tx_hashes.. detect which and act accordingly
            if Address.is_valid(key):
                hist = self.get([Address.from_string(key)]) # recursively call self with propery list data type, which will end up calling get_history (it's ok -- this is to cache results uniformly!)
                duped = ' (duped) '
            elif gui.ElectrumGui.gui.wallet and gui.ElectrumGui.gui.wallet.transactions.get(key, None):
                fullHist = self.get(None) # recursively call self to get a full history (will be cached so it's ok!)
                try:
                    hentry = fullHist.get_by_txid(key)
                    hist.append(hentry)
                except KeyError:
                    pass
            else:
                unk = True
        else:
            unk = True
        dstr = str(key) if not isinstance(key, contacts.ContactsEntry) else '[ContactsEntry: ' + key.address_str + ']'
        if unk:
            utils.NSLog("HistoryMgr: failed to retrieve any data for unknown domain=%s, returning empty list",dstr[:80])
        else:
            time_taken = time.time()-t0
            utils.NSLog("HistoryMgr: refresh %d entries for domain=%s in %f ms%s (hist result type=%s)", len(hist), dstr[:80],time_taken*1e3,duped,''.join(list(str(type(hist)))[-19:-2]))
            gui.ElectrumGui.gui.refresh_cost('history', time_taken)
        return hist

import threading
class ContactsHistorySynchronizer(utils.PySig):
    def __init__(self, parent): # parent must be a gui.ElectrumGui object
        super().__init__()
        self.parent = parent
        self.eventFlag = threading.Event()
        self.stopFlag = threading.Event()
        self.lock = threading.RLock()
        self.thread = None
    def __del__(self):
        self.stop()
        super().__del__()
    def wallet_name(self):
        ret = '<None>'
        if self.parent.wallet and self.parent.wallet.storage:
            ret = os.path.split(self.parent.wallet.storage.path)[1]
        return ret
    def _synchronizer(self):
        self.print_error("Started (wallet=%s)..." % self.wallet_name())
        last_seen_len, announce = (0, False)
        while not self.stopFlag.is_set():
            if self.eventFlag.wait():
                if self.stopFlag.is_set():
                    break
                wallet = self.parent.wallet
                storage = wallet.storage if wallet else None
                full = None
                self.print_error("Woke Up...")
                if wallet and storage:
                    with self.lock:
                        full = self._synch_full(wallet)
                        for addrstr, d in full.items():
                            k = 'contact_history_%s' % (addrstr)
                            if storage.get(k) != d:
                                storage.put(k, d)
                                announce = True
                                self.print_error('Wrote %s...' % k)
                full_len = len(full) if full else 0
                if announce or last_seen_len != full_len:
                    self.print_error("Contact history updated, announcing...")
                    self.emit()
                    announce = False
                else:
                    self.print_error("No new contact history.")
                last_seen_len = full_len
                self.eventFlag.clear()
        self.print_error("Stopping! (wallet=%s)" % self.wallet_name())
    def _notify_needs_synch(self):
        if not self.eventFlag.is_set():
            self.eventFlag.set()
    def restart(self):
        self.stop()
        self.start()
    def start(self):
        if not self.thread:
            self.thread = threading.Thread(name='ContactsHistorySynchronizer', target=self._synchronizer)
        if not self.thread.is_alive():
            self.stopFlag.clear()
            self.thread.start()
            self.parent.sigHistory.connect(self._notify_needs_synch)
            self.parent.sigContacts.connect(self._notify_needs_synch)
    def stop(self):
        if self.thread and self.thread.is_alive():
            self.parent.sigHistory.disconnect(self._notify_needs_synch)
            self.parent.sigContacts.disconnect(self._notify_needs_synch)
            self.stopFlag.set()
            self.eventFlag.set()
            self.thread.join()
            self.thread = None
            self.stopFlag.clear()
            self.eventFlag.clear()
    def get_history(self, address : Address) -> list:
        ret = list()
        if isinstance(address, str) and Address.is_valid(address):
            address = Address.from_string(address)
        storage = self.parent.wallet.storage if self.parent.wallet else None
        if storage:
            addrstr = address.to_storage_string()
            k = 'contact_history_%s' % (addrstr)
            hdict = storage.get(k)
            if hdict:
                ret = list(hdict.values())
                ret.sort(key=lambda x: x[1], reverse=True)
        return ret
    def delete_history(self, address : Address) -> None:
        if isinstance(address, str) and Address.is_valid(address):
            address = Address.from_string(address)
        storage = self.parent.wallet.storage if self.parent.wallet else None
        if storage:
            with self.lock:
                addrstr = address.to_storage_string()
                k = 'contact_history_%s' % (addrstr)
                storage.put(k, None)
                self.print_error("Deleted %s" % addrstr)
    @profiler
    def _synch_full(self, wallet):
        c = self._get_contacts(wallet)
        if not c:
            # short-circuit abort function early if no contacts exist.
            return dict()
        h = self._get_history(wallet)
        seen = dict() # Address -> dict of tx_hash_str -> hitem tuple
        for hitem in h:
            # loop through ALL the history and see if relevant tx's exist for contacts we care about
            tx_hash = hitem[0]
            tx = wallet.transactions.get(tx_hash)
            if tx:
                tx.deserialize()
                ins = tx.inputs()
                for x in ins:
                    xa = x['address']
                    if isinstance(xa, PublicKey):
                        xa = xa.toAddress()
                    if isinstance(xa, Address) and xa in c:
                        dct = seen.get(xa, dict())
                        wasEmpty = not dct
                        if tx_hash not in dct:
                            dct[tx_hash] = hitem
                            if wasEmpty: seen[xa] = dct
                outs = tx.get_outputs()
                for x in outs:
                    xa, dummy = x
                    if isinstance(xa, Address) and xa in c:
                        dct = seen.get(xa, dict())
                        wasEmpty = not dct
                        if tx_hash not in dct:
                            dct[tx_hash] = hitem
                            if wasEmpty: seen[xa] = dct
        storable = dict()
        for addr,d in seen.items():
            addrstr = addr.to_storage_string()
            storable[addrstr] = d
        return storable
    def _get_contacts(self, wallet):
        conts = contacts.get_contacts(wallet=wallet,sort=False)
        ret = dict()
        for c in conts:
            ret[c.address] = c
        return ret
    def _get_history(self, wallet):
        h = wallet.get_history(None)
        h.reverse()
        return h

def get_contact_history(address : Address) -> list:
    hitems = gui.ElectrumGui.gui.contactHistSync.get_history(address)
    ret = _HistoryListProxy()
    ret.set_hitems(hitems)
    #utils.NSLog("get_contact_history: Returning history of size %d for %s",len(ret),address.to_storage_string())
    return ret

def delete_contact_history(address : Address) -> None:
    gui.ElectrumGui.gui.contactHistSync.delete_history(address)

_tx_cell_height = 76.0 # TxHistoryCell height in points
_date_width = None
_is_ipad = utils.is_ipad()

class TxHistoryHelper(TxHistoryHelperBase):
    haveShowMoreTxs = objc_property()

    @objc_method
    def dealloc(self) -> None:
        #cleanup code here
        print("TxHistoryHelper dealloc")
        gui.ElectrumGui.gui.sigHistory.disconnect(self)
        self.haveShowMoreTxs = None
        utils.nspy_pop(self) # clear 'txs' python dict
        send_super(__class__, self, 'dealloc')

    @objc_method
    def miscSetup(self) -> None:
        nib = UINib.nibWithNibName_bundle_("TxHistoryCell", None)
        self.tv.registerNib_forCellReuseIdentifier_(nib, "TxHistoryCell")
        self.tv.refreshControl = gui.ElectrumGui.gui.helper.createAndBindRefreshControl()
        def gotRefresh() -> None:
            if self.tv:
                if self.tv.refreshControl: self.tv.refreshControl.endRefreshing()
                self.tv.reloadData()
        gui.ElectrumGui.gui.sigHistory.connect(gotRefresh, self)

    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        h = _GetTxs(self)
        rows = 0
        self.haveShowMoreTxs = False
        len_h = len(h) if h else 0
        if not self.compactMode:
            rows = len_h
        else:
            rows = max(math.floor(tableView.bounds.size.height / _tx_cell_height), 1)
            rows = min(rows,len_h)
            self.haveShowMoreTxs = len_h > rows
        return rows

    @objc_method
    def tableView_viewForFooterInSection_(self, tv, section : int) -> ObjCInstance:
        if self.haveShowMoreTxs:
            v = None
            objs = NSBundle.mainBundle.loadNibNamed_owner_options_("WalletsMisc",None,None)
            for o in objs:
                if not v and isinstance(o,UIView) and o.tag == 3000:
                    v = o
                    l = v.viewWithTag_(1)
                    if l: l.text = _("Show All Transactions")
            for o in objs:
                if isinstance(o, UIGestureRecognizer) and o.view and v \
                       and o.view.ptr.value == v.ptr.value:
                    o.addTarget_action_(self, SEL(b'onSeeAllTxs:'))
            return v
        return UIView.alloc().initWithFrame_(CGRectMake(0,0,0,0)).autorelease()

    @objc_method
    def onSeeAllTxs_(self, gr : ObjCInstance) -> None:
        if gr.view.hasAnimations:
            print("onSeeAllTxs: animation already active, ignoring spurious second tap....")
            return
        def seeAllTxs() -> None:
            # Push a new viewcontroller that contains just a tableview.. we create another instance of this
            # class to manage the tableview and set it up properly.  This should be fast as we are sharing tx history
            # data with the child instance via our "nspy_put" mechanism.
            vc = UIViewController.new().autorelease()
            vc.title = _("All Transactions")
            bb = UIBarButtonItem.new().autorelease()
            bb.title = _("Back")
            vc.navigationItem.backBarButtonItem = bb
            vc.view = UITableView.alloc().initWithFrame_style_(self.vc.view.frame, UITableViewStylePlain).autorelease()
            vc.view.separatorInset = UIEdgeInsetsZero
            helper = NewTxHistoryHelper(tv = vc.view, vc = self.vc, domain = _GetDomain(self))
            self.vc.navigationController.pushViewController_animated_(vc, True)
        #c = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.10)
        #gr.view.backgroundColorAnimationToColor_duration_reverses_completion_(c,0.2,True,seeAllTxs)
        gr.view.viewWithTag_(1).textColorAnimationFromColor_toColor_duration_reverses_completion_(
            utils.uicolor_custom('link'), utils.uicolor_custom('linktapped'), 0.2, True, seeAllTxs
        )

    @objc_method
    def tableView_heightForFooterInSection_(self, tv, section : int) -> float:
        if self.compactMode:
            return 50.0
        return 0.0

    @objc_method
    def emptyCell_(self, tableView : ObjCInstance) -> ObjCInstance:
        identifier = "Cell"
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        if cell is None:
            cell =  UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, identifier).autorelease()
        cell.textLabel.text = _("No transactions")
        cell.textLabel.textColor = utils.uicolor_custom('dark')
        cell.detailTextLabel.text = _("No transactions were found on the blockchain.")
        cell.detailTextLabel.font = UIFont.italicSystemFontOfSize_(12.0)
        cell.detailTextLabel.textColor = utils.uicolor_custom('light')
        return cell

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath) -> ObjCInstance:
        h = _GetTxs(self)
        if not h or indexPath.row >= len(h):
            return self.emptyCell_(tableView)
        identifier = "TxHistoryCell"
        cell = tableView.dequeueReusableCellWithIdentifier_(identifier)
        global _date_width
        if _date_width is None:
            _date_width = cell.dateWidthCS.constant
        #HistoryEntry = tx tx_hash status_str label v_str balance_str date ts conf status value fiat_amount fiat_balance fiat_amount_str fiat_balance_str ccy status_image
        entry = h[indexPath.row]
        if entry is None:
            return self.emptyCell_(tableView)
        ff = '' #str(entry.date)
        if entry.conf and entry.conf > 0 and entry.conf < 6:
            ff = "%s %s"%(entry.conf, _('confirmations'))

        cell.amountTit.setText_withKerning_(_("Amount"), utils._kern)
        cell.balanceTit.setText_withKerning_(_("Balance"), utils._kern)
        cell.statusTit.setText_withKerning_(_("Status"), utils._kern)
        amtStr = utils.stripAmount(entry.v_str)
        balStr = utils.stripAmount(entry.balance_str)
        if (self.compactMode and not _is_ipad) or (not entry.fiat_amount_str and not entry.fiat_balance_str):
            if cell.amount.numberOfLines != 1:
                cell.amount.numberOfLines = 1
                cell.balance.numberOfLines = 1
            if cell.dateWidthCS.constant != _date_width:
                cell.dateWidthCS.constant = _date_width
            cell.amount.text = amtStr
            cell.balance.text = balStr
        else:
            # begin experimental fiat history rates zone
            cell.amount.numberOfLines = 0
            cell.balance.numberOfLines = 0
            cell.dateWidthCS.constant = _date_width
            s1 = ns_from_py(amtStr).sizeWithAttributes_({NSFontAttributeName:utils._f1})
            s2 = ns_from_py(balStr).sizeWithAttributes_({NSFontAttributeName:utils._f1})
            def adjustCS() -> None:
                if _is_ipad:
                    pass
                else:
                    cell.dateWidthCS.constant = _date_width - 24.0
            cell.amount.attributedText = utils.hackyFiatAmtAttrStr(amtStr,utils.stripAmount(entry.fiat_amount_str),entry.ccy,s2.width-s1.width,utils.uicolor_custom('light'),adjustCS,utils._kern*1.25, isIpad=_is_ipad)
            cell.balance.attributedText = utils.hackyFiatAmtAttrStr(balStr,utils.stripAmount(entry.fiat_balance_str),entry.ccy,s1.width-s2.width,utils.uicolor_custom('light'),adjustCS,utils._kern*1.25, isIpad=_is_ipad)
            # end experimental zone...
        cell.desc.setText_withKerning_(entry.label.strip() if isinstance(entry.label, str) else '', utils._kern)
        cell.icon.image = UIImage.imageNamed_("tx_send.png") if entry.value and entry.value < 0 else UIImage.imageNamed_("tx_recv.png")
        if entry.conf > 0:
            cell.date.attributedText = utils.makeFancyDateAttrString(entry.status_str.strip())
        else:
            cell.date.text = entry.status_str.strip()
        cell.status.text = ff #if entry.conf < 6 else ""
        cell.statusIcon.image = entry.status_image

        return cell

    @objc_method
    def tableView_heightForRowAtIndexPath_(self, tv : ObjCInstance, indexPath : ObjCInstance) -> float:
        return _tx_cell_height if indexPath.row > 0 or _GetTxs(self) else 44.0

    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        tv.deselectRowAtIndexPath_animated_(indexPath,True)
        parent = gui.ElectrumGui.gui
        if parent.wallet is None:
            return
        if not self.vc:
            utils.NSLog("TxHistoryHelper: No self.vc defined, cannot proceed to tx detail screen")
            return
        tx = None
        try:
            entry = _GetTxs(self)[indexPath.row]
            if entry.tx:
                tx = entry.tx
            else:
                tx = parent.wallet.transactions.get(entry.tx_hash, None)
        except:
            return
        if tx is None:
            # I'm not sure why this would happen but we did get issue #810 where it happened to 1 user.
            # Perhaps a chain split led to an "old" history view on-screen.  That's my theory, at least. -Calin
            parent.show_error(_("The requested transaction has dropped out of the wallet history.\n\nIf this problem persists, please contact us at electroncash.org."),
                              title = _("Transaction Not Found"),
                              onOk = lambda: parent.refresh_components('history'))
            return
        txd = txdetail.CreateTxDetailWithEntry(entry,tx=tx)
        self.vc.navigationController.pushViewController_animated_(txd, True)

class TxHistoryHelperWithHeader(TxHistoryHelper):
    @objc_method
    def tableView_viewForHeaderInSection_(self, tv : ObjCInstance,section : int) -> ObjCInstance:
        objs = NSBundle.mainBundle.loadNibNamed_owner_options_("TableHeaders", None, None)
        for o in objs:
            if isinstance(o, UIView) and o.tag == 10000:
                label = o.viewWithTag_(1)
                if label: label.text = _("Transaction History")
                return o
        return UIView.alloc().initWithFrame_(CGRectMake(0.0,0.0,0.0,0.0)).autorelease()
    @objc_method
    def tableView_heightForHeaderInSection_(self, tv : ObjCInstance,section : int) -> float:
        return 28.0

def NewTxHistoryHelper(tv : ObjCInstance, vc : ObjCInstance, domain : list = None, noRefreshControl = False, cls : ObjCClass=None) -> ObjCInstance:
    if not cls:
        cls = TxHistoryHelper
    helper = cls.new().autorelease()
    if tv.delegate and tv.dataSource and tv.delegate == tv.dataSource and isinstance(tv.delegate, TxHistoryHelper):
        TxHistoryHelperDissociate(tv.delegate)
    tv.dataSource = helper
    tv.delegate = helper
    helper.tv = tv
    helper.vc = vc
    # optimization to share the same history data with the new helper class we just created for the full mode view
    # .. hopefully this will keep the UI peppy and responsive!
    if domain is not None:
        utils.nspy_put_byname(helper, domain, 'domain')
    helper.miscSetup()
    if noRefreshControl: helper.tv.refreshControl = None
    from rubicon.objc.runtime import libobjc
    libobjc.objc_setAssociatedObject(tv.ptr, helper.ptr, helper.ptr, 0x301)
    return helper

def TxHistoryHelperDissociate(helper):
    if helper and helper.tv:
        if helper.tv.dataSource: helper.tv.dataSource = None
        if helper.tv.delegate: helper.tv.delegate = None
        helper.vc = None
        # below clears object association -- will auto-release the helper as a side-effect
        from rubicon.objc.runtime import libobjc
        theTV = helper.tv
        helper.tv = None
        if libobjc.objc_getAssociatedObject(theTV.ptr, helper.ptr).value == helper.ptr.value:
            libobjc.objc_setAssociatedObject(theTV.ptr, helper.ptr, None, 0x301)


# this should be a method of TxHistoryHelper but it returns a python object, so it has to be a standalone global function
def _GetTxs(txsHelper : object) -> list:
    if not txsHelper:
        raise ValueError('GetTxs: Need to specify a TxHistoryHelper instance')
    h = gui.ElectrumGui.gui.sigHistory.get(_GetDomain(txsHelper))
    return h

def _GetDomain(txsHelper : object) -> list:
    if not txsHelper:
        raise ValueError('GetDomain: Need to specify a TxHistoryHelper instance')
    return utils.nspy_get_byname(txsHelper, 'domain')

def Find(tx_hash_or_address : str) -> HistoryEntry:
    if not isinstance(tx_hash_or_address, str): return None
    h = gui.ElectrumGui.gui.sigHistory.get(tx_hash_or_address)
    if h and len(h): return h[0]
    return None
