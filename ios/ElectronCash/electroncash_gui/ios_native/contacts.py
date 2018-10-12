#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
from . import utils
from . import gui
from electroncash import WalletStorage, Wallet
from electroncash.util import timestamp_to_datetime
from electroncash.i18n import _, language
from electroncash.address import Address, PublicKey
from .uikit_bindings import *
from .custom_objc import *
from collections import namedtuple
import time, sys, traceback

ContactsEntry = namedtuple("ContactsEntry", "name address address_str")

from . import history

_CellIdentifier = "ContactsCell"  # New UI cell identifier

ModeNormal = 0
ModePicker = 1


class ContactsVC(ContactsVCBase):
    ''' New UI style Contacts tab and modal picker '''
    needsRefresh = objc_property()
    blockRefresh = objc_property()
    mode = objc_property()
    pickSingle = objc_property()
    addBut = objc_property()
    doneBut = objc_property()
    cancelBut = objc_property()
    selected = objc_property()
    hax = objc_property()

    # preferred c'tor
    @objc_method
    def initWithMode_(self, mode : int) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.commonInitWithMode_(mode)
        return self

    @objc_method
    def init(self) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'init'))
        if self:
            self.commonInitWithMode_(ModeNormal)
        return self
    @objc_method
    def initWithCoder(self, coder : ObjCInstance) -> ObjCInstance:
        self = ObjCInstance(send_super(__class__, self, 'initWithCoder:', coder, argtypes=[objc_id]))
        if self:
            self.commonInitWithMode_(ModeNormal)
        return self

    @objc_method
    def commonInitWithMode_(self, mode : int) -> None:
        self.mode = ModeNormal if mode == ModeNormal else ModePicker
        self.needsRefresh = False
        self.blockRefresh = False
        self.pickSingle = True
        self.tabBarItem.image = UIImage.imageNamed_("tab_contacts_new.png")
        self.title = _("Contacts")
        self.hax = False

        self.selected = []
        self.addBut = None
        self.doneBut = None
        self.cancelBut = None

        if self.mode == ModePicker:
            lbuts = [
                UIBarButtonItem.alloc().initWithBarButtonSystemItem_target_action_(UIBarButtonSystemItemCancel, self, SEL(b'onPickerCancel')).autorelease(),
            ]
            buts = [
                UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_chk"), UIBarButtonItemStyleDone, self, SEL(b'onPickerPayTo')).autorelease(),
                UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_plus"), UIBarButtonItemStylePlain, self, SEL(b'onAddBut')).autorelease(),
            ]
            self.cancelBut = lbuts[0]
            self.doneBut = buts[0]
            self.addBut = buts[1]
            self.doneBut.enabled = False
            self.cancelBut.enabled = True
            self.navigationItem.rightBarButtonItems = buts
            self.navigationItem.leftBarButtonItems = lbuts
        else:
            buts = [
                UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_plus"), UIBarButtonItemStylePlain, self, SEL(b'onAddBut')).autorelease(),
                #UIBarButtonItem.alloc().initWithTitle_style_target_action_(_("Pay to"), UIBarButtonItemStyleDone, self, SEL(b'onPickerPayTo')).autorelease(),
            ]
            self.addBut = buts[0]
            #self.doneBut = buts[1]
            self.navigationItem.rightBarButtonItems = buts

        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb

    @objc_method
    def dealloc(self) -> None:
        # do cleanup stuff here
        gui.ElectrumGui.gui.sigContacts.disconnect(self)
        gui.ElectrumGui.gui.contactHistSync.disconnect(self)
        self.needsRefresh = None
        self.blockRefresh = None
        self.selected = None
        self.mode = None
        self.cancelBut = None
        self.doneBut = None
        self.addBut = None
        self.pickSingle = None
        self.hax = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        send_super(__class__, self, 'dealloc')

    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("Contacts", self, None) # auto-binds self.view
        if self.tv:
            self.tv.refreshControl = gui.ElectrumGui.gui.helper.createAndBindRefreshControl()
            self.refreshControl = self.tv.refreshControl
            uinib = UINib.nibWithNibName_bundle_(_CellIdentifier, None)
            self.tv.registerNib_forCellReuseIdentifier_(uinib, _CellIdentifier)

        # workaround for inability to specify attributed text font italic in IB for some bizarre reason
        ats = NSMutableAttributedString.alloc().initWithAttributedString_(self.noContactsLabel.attributedText).autorelease()
        r = NSRange(0,ats.length())
        ats.removeAttribute_range_(NSFontAttributeName,r)
        ats.addAttribute_value_range_(NSFontAttributeName,UIFont.italicSystemFontOfSize_(14.0),r)
        ats.addAttribute_value_range_(NSKernAttributeName,-0.5,r)
        self.noContactsLabel.attributedText = ats
        utils.uilabel_replace_attributed_text(lbl = self.noContactsLabel,
                                              # translate text for i18n
                                              text = _("You don't have any contacts yet. Create a new contact now!"),
                                              template = self.noContactsLabel.attributedText)
        # /end workaround
        for state in UIControlState_ALL_RELEVANT_TUPLE:
            # translate text
            self.butBottom.setTitle_forState_(_('New contact'), state)
        # Can't set this property from IB, so we do it here programmatically to create the stroke around the New contact bottom button
        self.butBottom.layer.borderColor = self.butBottom.titleColorForState_(UIControlStateNormal).CGColor


    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        gui.ElectrumGui.gui.sigContacts.connect(lambda:self.refresh(), self)
        gui.ElectrumGui.gui.contactHistSync.connect(lambda:self.refresh(), self)
        self.refresh()

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        presel = utils.nspy_get_byname(self, 'preselected')
        if presel:
            utils.nspy_pop_byname(self, 'preselected')
            self.selected = [presel]
            self.selected = self.updateSelectionButtons()
            self.tv.reloadData()

    #### UITableView delegate/dataSource methods...
    @objc_method
    def numberOfSectionsInTableView_(self, tableView) -> int:
        return 1

    @objc_method
    def tableView_numberOfRowsInSection_(self, tableView, section : int) -> int:
        try:
            contacts = _Get()
            return len(contacts) if contacts else 0
        except Exception as e:
            utils.NSLog("Error, exception retrieving contacts: %s",str(e))
            return 0

    @objc_method
    def tableView_cellForRowAtIndexPath_(self, tableView, indexPath):
        try:
            contacts = _Get()
            cell = tableView.dequeueReusableCellWithIdentifier_(_CellIdentifier)
            if cell is None: raise Exception('Cell was None!')
            parent = gui.ElectrumGui.gui
            if contacts:
                cell.address.tag = indexPath.row # associate the tapped 'link' with this contact
                c = contacts[indexPath.row]
                cell.name.text = c.name
                hist = history.get_contact_history(c.address)
                cell.numTxs.text = str(len(hist) if hist else 0) + " " + _('Transactions')
                enabledLink = self.mode == ModeNormal
                if enabledLink:
                    cell.address.textColor = utils.uicolor_custom('link')
                    cell.address.userInteractionEnabled = True
                    cell.address.linkText = c.address_str
                    def target(add : objc_id) -> None:
                        if self.navigationController and self.navigationController.visibleViewController.ptr == self.ptr:
                            self.onTapAddress_(ObjCInstance(add))
                    cell.address.linkTarget = target
                else:
                    cell.address.attributedText = None
                    cell.address.textColor = utils.uicolor_custom('dark')
                    cell.address.userInteractionEnabled = False
                    cell.address.text = c.address_str
                    cell.address.linkTarget = None
                    cell.address.linkWillAnimate = None
                self.setupAccessoryForCell_atIndex_(cell, indexPath.row)
        except:
            #import traceback
            #traceback.print_exc()
            utils.NSLog("exception in Contacts tableView_cellForRowAtIndexPath_: %s",str(sys.exc_info()[1]))
            cell = UITableViewCell.alloc().initWithStyle_reuseIdentifier_(UITableViewCellStyleSubtitle, "ACell").autorelease()
            empty_cell(cell, txt = "")
        return cell

    # Below 2 methods conform to UITableViewDelegate protocol
    @objc_method
    def tableView_accessoryButtonTappedForRowWithIndexPath_(self, tv, indexPath):
        #print("ACCESSORY TAPPED CALLED")
        pass


    @objc_method
    def tableView_didSelectRowAtIndexPath_(self, tv, indexPath):
        #print("DID SELECT ROW CALLED FOR ROW %d"%indexPath.row)
        tv.deselectRowAtIndexPath_animated_(indexPath,False)
        cell = tv.cellForRowAtIndexPath_(indexPath)

        contacts = _Get()
        if not contacts or indexPath.row >= len(contacts): return

        if self.mode == ModePicker:
            if not self.pickSingle:
                self.setIndex_selected_(indexPath.row, not self.isIndexSelected_(indexPath.row))
                wasSel = self.setupAccessoryForCell_atIndex_(cell, indexPath.row) # this sometimes fails if address is frozen and/or we are watching only
                self.setIndex_selected_(indexPath.row, wasSel)

                self.selected = self.updateSelectionButtons()
            else:
                # force only 1 contact to be selected, clearing all others
                self.selected = [contacts[indexPath.row].address_str] if not self.isIndexSelected_(indexPath.row) else []
                self.selected = self.updateSelectionButtons()
                self.tv.reloadData() # force redraw of all checkmarks
        else:
            if self.navigationController:
                PushNewContactDetailVC(contacts[indexPath.row], self.navigationController)

    @objc_method
    def tableView_editingStyleForRowAtIndexPath_(self, tv, indexPath) -> int:
        contacts = _Get()
        if self.mode == ModePicker or not contacts or not len(contacts):
            return UITableViewCellEditingStyleNone
        return UITableViewCellEditingStyleDelete

    @objc_method
    def tableView_commitEditingStyle_forRowAtIndexPath_(self, tv, editingStyle : int, indexPath) -> None:
        contacts = _Get()
        if not contacts or indexPath.row < 0 or indexPath.row >= len(contacts): return
        if editingStyle == UITableViewCellEditingStyleDelete:
            if delete_contact(contacts[indexPath.row]):
                was = self.blockRefresh
                self.blockRefresh = True
                _Updated()
                contacts = _Get()
                self.needsRefresh = False
                if len(contacts):
                    if not self.hax:
                        tv.deleteRowsAtIndexPaths_withRowAnimation_([indexPath],UITableViewRowAnimationFade)
                    self.selected = self.updateSelectionButtons()
                    self.blockRefresh = was
                else:
                    self.blockRefresh = was
                    self.refresh()

    @objc_method
    def tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_(self, tv, indexPath) -> ObjCInstance:
        ''' This method is called in iOS 11.0+ only .. so we only create this UISwipeActionsConfiguration ObjCClass
            here rather than in uikit_bindings.py
        '''
        try:
            row = int(indexPath.row) # save param outside objcinstance object and into python for 'handler' closure
            section = int(indexPath.section)
            def handler(a : objc_id, v : objc_id, c : objc_id) -> None:
                result = False
                try:
                    ip = NSIndexPath.indexPathForRow_inSection_(row,section)
                    self.hax = True
                    self.tableView_commitEditingStyle_forRowAtIndexPath_(tv, UITableViewCellEditingStyleDelete, ip)
                    self.hax = False
                    result = True
                except:
                    traceback.print_exc(file=sys.stderr)
                ObjCBlock(c)(bool(result)) # inform UIKit if we deleted it or not by calling the block handler callback
            action = UIContextualAction.contextualActionWithStyle_title_handler_(UIContextualActionStyleDestructive,
                                                                                 _("Remove"),
                                                                                 Block(handler))
            action.image = UIImage.imageNamed_("trashcan_red.png")
            action.backgroundColor = utils.uicolor_custom('red')
            return UISwipeActionsConfiguration.configurationWithActions_([action])
        except:
            utils.NSLog("ContactsTV.tableView_trailingSwipeActionsConfigurationForRowAtIndexPath_, got exception: %s", str(sys.exc_info()[1]))
            traceback.print_exc(file=sys.stderr)
        return None

    ### end UITableView related methods

    @objc_method
    def refresh(self):
        if self.viewIfLoaded:
            self.needsRefresh = True # mark that a refresh was called in case refresh is blocked
            if self.blockRefresh:
                return
            if self.refreshControl: self.refreshControl.endRefreshing()
            self.selected = self.updateSelectionButtons()
            self.tv.reloadData()
            self.doChkEmpty()
        self.needsRefresh = False

    @objc_method
    def doRefreshIfNeeded(self):
        if self.needsRefresh:
            self.refresh()


    @objc_method
    def doChkEmpty(self):
        contacts = _Get()
        if contacts:
            self.noContacts.setHidden_(True)
            self.tv.setHidden_(False)
        else:
            self.noContacts.setHidden_(False)
            self.tv.setHidden_(True)

    @objc_method
    def isIndexSelected_(self, index : int) -> bool:
        try:
            entry = _Get()[index]
            sels = set(list(self.selected))
            return bool(entry.address_str in sels)
        except:
            import sys
            utils.NSLog("Exception during contacts.py 'isIndexSelected': %s",str(sys.exc_info()[1]))
        return False

    @objc_method
    def setIndex_selected_(self, index : int, b : bool) -> None:
        try:
            entry = _Get()[index]
            sels = set(list(self.selected))
            if not b: sels.discard(entry.address_str)
            else: sels.add(entry.address_str)
            self.selected = list(sels)
        except:
            import sys
            utils.NSLog("Exception during contacts.py 'setIndex_selected_': %s",str(sys.exc_info()[1]))

    @objc_method
    def onPickerCancel(self) -> None:
        print ("picker cancel...")
        self.presentingViewController.dismissViewControllerAnimated_completion_(True, None)

    @objc_method
    def onPickerPayTo(self) -> None:
        #print ("picker done/payto...")
        validSels = list(self.updateSelectionButtons())
        #print("valid selections:",*validSels)
        contacts = _Get()
        addys = []
        for entry in contacts:
            if entry.address_str in validSels:
                addys.append(entry.address_str)
        if addys:
            if self.mode == ModePicker:
                utils.get_callback(self, 'on_pay_to')(addys)
            else:
                pay_to(addys)


    @objc_method
    def onTapAddress_(self, view : ObjCInstance) -> None:
        if not isinstance(view, UILabel):
            return
        try:
            contact = _Get()[view.tag]
        except:
            return
        show_contact_options_actionsheet(contact, self, view, onEdit = lambda x: utils.show_notification(_("Contact saved")))


    @objc_method
    def updateSelectionButtons(self) -> ObjCInstance:
        parent = gui.ElectrumGui.gui
        newSels = set()
        if self.doneBut: self.doneBut.enabled = False
        if parent.wallet:
            sels = set(list(self.selected))
            contacts = _Get()
            for c in contacts:
                if c.address_str in sels:
                    newSels.add(c.address_str)
            if len(newSels) and self.doneBut:
                self.doneBut.enabled = True
        return ns_from_py(list(newSels))

    @objc_method
    def setupAccessoryForCell_atIndex_(self, cell, index : int) -> bool:
        parent = gui.ElectrumGui.gui
        no_good = parent.wallet is None or parent.wallet.is_watching_only()
        try:
            entry = _Get()[index]
        except:
            no_good = True

        ret = False

        if no_good or not self.isIndexSelected_(index) or self.mode == ModeNormal:
            cell.customAccessory.image = UIImage.imageNamed_("circle2" if self.mode == ModePicker else "chevron_gray_right")
        else:
            cell.customAccessory.image = UIImage.imageNamed_("bluechk")
            ret = True

        return ret

    @objc_method
    def showNewEditForm_(self, index : int) -> None:
        contact = None
        if index > -1:
            contacts = _Get()
            if contacts and index < len(contacts):
                contact = contacts[index]
        show_new_edit_contact(contact, self, onEdit = lambda x: utils.show_notification(_("Contact saved")))


    @objc_method
    def onAddBut(self) -> None:
        self.showNewEditForm_(-1)



class NewContactVC(NewContactBase):

    qr = objc_property()
    qrvc = objc_property()
    editMode = objc_property()

    @objc_method
    def dealloc(self) -> None:
        self.qrvc = None
        self.qr = None
        self.editMode = None
        utils.nspy_pop(self)
        utils.remove_all_callbacks(self)
        print("NewContactVC dealloc")
        send_super(__class__, self, 'dealloc')

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')


    @objc_method
    def onOk(self) -> None:
        #print("On OK...")
        address_str = cleanup_address_remove_colon(self.address.text)
        name = str(self.name.text).strip()
        if not Address.is_valid(address_str):
            gui.ElectrumGui.gui.show_error(_("Invalid Address"), title=self.title)
            return
        if not name:
            gui.ElectrumGui.gui.show_error(_("Name is empty"), title=self.title)
            return
        def doCB() -> None:
            cb = utils.get_callback(self, 'on_ok')
            if callable(cb):
                entry = None
                if name and address_str and Address.is_valid(address_str):
                    address = Address.from_string(address_str)
                    entry = ContactsEntry(name, address, address_str)
                cb(entry)
            self.autorelease()
        self.retain()
        self.presentingViewController.dismissViewControllerAnimated_completion_(True, doCB)

    @objc_method
    def onCancel(self) -> None:
        #print("On Cancel...")
        def doCB() -> None:
            cb = utils.get_callback(self, 'on_cancel')
            if callable(cb): cb()
            self.autorelease()
        self.retain()
        self.presentingViewController.dismissViewControllerAnimated_completion_(True, doCB)

    @objc_method
    def onQR(self) -> None:
        #print("On QR...")
        if not QRCodeReader.isAvailable:
            utils.show_alert(self, _("QR Not Avilable"), _("The camera is not available for reading QR codes"))
        else:
            self.qr = QRCodeReader.new().autorelease()
            self.qrvc = QRCodeReaderViewController.readerWithCancelButtonTitle_codeReader_startScanningAtLoad_showSwitchCameraButton_showTorchButton_("Cancel",self.qr,True,False,False)
            self.qrvc.modalPresentationStyle = UIModalPresentationFormSheet
            self.qrvc.delegate = self
            self.presentViewController_animated_completion_(self.qrvc, True, None)

    @objc_method
    def onCpy_(self, sender) -> None:
        try:
            datum = str(self.name.text) if sender.ptr.value == self.cpyNameBut.ptr.value else str(self.address.text)
            msgPfx = "Name" if sender.ptr.value == self.cpyNameBut.ptr.value else "Address"

            gui.ElectrumGui.gui.copy_to_clipboard(datum, msgPfx)
            print ("copied to clipboard =", datum)
        except:
            import sys
            utils.NSLog("Exception during NewContactVC 'onCpy_': %s",str(sys.exc_info()[1]))

    @objc_method
    def reader_didScanResult_(self, reader, result) -> None:
        utils.NSLog("Reader data = '%s'",str(result))
        result = cleanup_address_remove_colon(result)
        if not Address.is_valid(result):
            title = _("Invalid QR Code")
            message = _("The QR code does not appear to be a valid BCH address.\nPlease try again.")
            reader.stopScanning()
            gui.ElectrumGui.gui.show_error(
                title = title,
                message = message,
                onOk = lambda: reader.startScanning(),
                vc = self.qrvc
            )
        else:
            self.address.text = result
            self.readerDidCancel_(reader)

    @objc_method
    def readerDidCancel_(self, reader) -> None:
        if reader is not None: reader.stopScanning()
        self.dismissViewControllerAnimated_completion_(True, None)
        self.qr = None
        self.qrvc = None

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        editContact = utils.nspy_get_byname(self, 'edit_contact')
        if editContact:
            self.editMode = True
            utils.nspy_pop_byname(self, 'edit_contact')
            utils.nspy_put_byname(self, editContact, 'old_contact')
            self.address.text = editContact.address_str
            self.name.text = editContact.name

        self.translateUI()

    @objc_method
    def translateUI(self) -> None:
        if not self.viewIfLoaded: return
        titleOverride = utils.nspy_get_byname(self, 'title_override')
        if not titleOverride:
            self.title = _("New Contact") if not self.editMode else _("Edit Contact")
        else:
            self.title = titleOverride
        #self.blurb.text = _("Contacts are a convenient feature to associate addresses with user-friendly names. "
        #                    "Contacts can be accessed when sending a payment via the 'Send' tab.") if not self.editMode else self.title
        self.addressTit.text = _("Address")
        self.nameTit.text = _("Name")
        self.name.placeholder = _("Satoshi Nakamoto")
        self.address.placeholder = _("Paste an address or use QR")

        tfwts = { self.name : 0, self.address : 1 }
        for tf in tfwts:
            tf.tag = tfwts[tf]
            utils.uitf_redo_attrs(tf) #this hackily reads tag for the font weight

    @objc_method
    def textFieldDidEndEditing_(self, tf : ObjCInstance) -> None:
        utils.uitf_redo_attrs(tf)

    @objc_method
    def textFieldDidBeginEditing_(self, tf : ObjCInstance) -> None:
        pass

    @objc_method
    def textFieldShouldReturn_(self, tf : ObjCInstance) -> bool:
        tf.resignFirstResponder()
        return True



class ContactDetailVC(ContactDetailVCBase):

    @objc_method
    def loadView(self) -> None:
        NSBundle.mainBundle.loadNibNamed_owner_options_("ContactDetail", self, None)

    @objc_method
    def viewDidLoad(self) -> None:
        send_super(__class__, self, 'viewDidLoad')
        self.title = _("Contact Info")
        self.navigationItem.rightBarButtonItem = UIBarButtonItem.alloc().initWithImage_style_target_action_(UIImage.imageNamed_("barbut_options"), UIBarButtonItemStylePlain, self, SEL(b'onOptions')).autorelease()
        self.payToBut.text = _("Pay to")
        bb = UIBarButtonItem.new().autorelease()
        bb.title = _("Back")
        self.navigationItem.backBarButtonItem = bb

    @objc_method
    def viewWillAppear_(self, animated : bool) -> None:
        send_super(__class__, self, 'viewWillAppear:', animated, argtypes=[c_bool])
        self.refresh()

    @objc_method
    def refresh(self) -> None:
        if not self.viewIfLoaded: return

        self.payToBut.setHidden_(gui.ElectrumGui.gui.wallet and gui.ElectrumGui.gui.wallet.is_watching_only())
        c = _Contact(self)
        if c:
            self.address.text = c.address_str
            self.name.text = c.name
            if not self.helper:
                self.helper = history.NewTxHistoryHelper(tv = self.tv, vc = self, noRefreshControl = True, cls = history.TxHistoryHelperWithHeader, domain = c)

        size = CGSizeMake(200.0,200.0) # the returned image has a 10 pix margin -- this compensates for it
        self.qr.contentMode = UIViewContentModeCenter # if the image pix margin changes -- FIX THIS
        self.qr.image = utils.get_qrcode_image_for_data(self.address.text, size = size)

        self.tv.reloadData()

    @objc_method
    def onPayTo(self) -> None:
        pay_to([self.address.text])

    @objc_method
    def onOptions(self) -> None:
        def onEdit(contact : ContactsEntry) -> None:
            old = _Contact(self)
            _SetContact(self, contact)
            if old.address_str != contact.address_str:
                '''
                Contact domain changed (user changed the address). The below self.helper = None will
                force a re-create of tx history helper for the new contact domain in the refresh() call that follows.
                (history.NewTxHistoryHelper() factory func will reap the old helper that was associated with self.tv as a side-effect)
                '''
                if self.helper:
                    self.helper = None
            self.refresh()
            utils.show_notification(_("Contact saved"))
        show_contact_options_actionsheet(_Contact(self), self, self.navigationItem.rightBarButtonItem, navBackOnDelete = True, onEdit = onEdit)

    @objc_method
    def cpyAddressToClipboard(self) -> None:
        gui.ElectrumGui.gui.copy_to_clipboard(str(self.address.text).strip(),"Address")
    @objc_method
    def cpyNameToClipboard(self) -> None:
        gui.ElectrumGui.gui.copy_to_clipboard(str(self.name.text).strip(),"Name")

    @objc_method
    def onQRImgTap(self) -> None:
        if not self.qr.image: gui.ElectrumGui.gui.show_error(vc = self, message = "Error, No QR Image")
        else:
            def ShowIt() -> None:
                utils.show_share_actions(vc = self, img = self.qr.image, ipadAnchor = self.qr.convertRect_toView_(self.qr.bounds, self.view), objectName = _("Image"))
            c1 = UIColor.clearColor
            c2 = UIColor.colorWithRed_green_blue_alpha_(0.0,0.0,0.0,0.3)
            self.qr.backgroundColorAnimationFromColor_toColor_duration_reverses_completion_(c1, c2, 0.2, True, ShowIt)



def _Contact(slf : ObjCInstance) -> ContactsEntry:
    return utils.nspy_get_byname(slf, 'contact_entry')

def _SetContact(slf : ObjCInstance, entry : ContactsEntry) -> None:
    utils.nspy_put_byname(slf, entry, 'contact_entry')

class ContactsMgr(utils.DataMgr):
    def doReloadForKey(self, key) -> list:
        # key is ignored
        return get_contacts() or list()

def _Get() -> list:
    return gui.ElectrumGui.gui.sigContacts.get(None)

def _Updated() -> None:
    gui.ElectrumGui.gui.refresh_components('contacts')

def Find(addy) -> ContactsEntry:
    if isinstance(addy, str):
        try:
            addy = Address.from_string(addy)
        except:
            return None
    contacts = _Get()
    if isinstance(addy, Address) and contacts:
        for c in contacts:
            if c.address == addy:
                return c
    return None


def get_contacts(wallet = None, sort = True) -> list:
    ''' Builds a list of
        ContactsEntry tuples:

        ContactsEntry = namedtuple("ContactsEntry", "name address address_str")

    '''
    t0 = time.time()
    if not wallet: wallet = gui.ElectrumGui.gui.wallet
    if wallet is None:
        utils.NSLog("get_contacts: wallent was None, returning early")
        return list()
    c = wallet.contacts
    contacts = list()
    for addr,tupl in c.items():
        typ, name = tupl
        if typ == 'address' and Address.is_valid(addr):
            address = Address.from_string(addr)
            entry = ContactsEntry(name, address, addr)
            contacts.append(entry)
    if sort:
        contacts.sort(key=lambda x: [x.name, x.address_str], reverse=False)
    #utils.NSLog("get_contacts: fetched %d contacts in %f ms",len(contacts), (time.time()-t0)*1000.0)
    return contacts

def delete_contact(entry : ContactsEntry, do_write = True) -> int:
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    if wallet is None:
        utils.NSLog("delete_contacts: wallent was None, returning early")
        return None
    c = wallet.contacts
    if not c:
        return None
    n = len(c)
    c.pop(entry.address_str)
    history.delete_contact_history(entry.address)
    n2 = len(c)
    if n2 < n:
        c.save()
        if do_write:
            c.storage.write()
    ret = n - n2
    utils.NSLog("deleted %d contact(s)", ret)
    return ret

def add_contact(entry : ContactsEntry, do_write = True) -> bool:
    parent = gui.ElectrumGui.gui
    wallet = parent.wallet
    if wallet is None:
        utils.NSLog("add_contact: wallent was None, returning early")
        return False
    c = wallet.contacts
    if c is None:
        utils.NSLog("add_contact: contacts was None, returning early")
        return False
    n = len(c)
    c[entry.address_str] = ("address", entry.name)
    n2 = len(c)
    c.save()
    if do_write:
        c.storage.write()
    ret = n2 - n
    utils.NSLog("added %d contact(s)", ret)
    return bool(ret)

def empty_cell(cell : ObjCInstance, txt : str = "*Error*", italic : bool = False) -> ObjCInstance:
    cell.textLabel.attributedText = None
    cell.textLabel.text = txt
    if italic:
        cell.textLabel.font = UIFont.italicSystemFontOfSize_(cell.textLabel.font.pointSize)
    else:
        cell.textLabel.font = UIFont.systemFontOfSize_(cell.textLabel.font.pointSize)
    cell.detailTextLabel.attributedText = None
    cell.detailTextLabel.text = None
    cell.accessoryType = UITableViewCellAccessoryNone
    cell.accessoryView = None
    cell.imageView.image = None
    return cell

def cleanup_address_remove_colon(result : str) -> str:
    if result is not None:
        result = str(result).strip()

        if ':' in result:
            try:
                result = ''.join(result.split(':')[1:])
            except:
                pass
    return result

def pay_to(addys : list) -> bool:
    print("payto:",*addys)
    if len(addys) > 1:
        gui.ElectrumGui.gui.show_error(title=_("Coming Soon"),
                                       message=_("This version of Electron Cash currently only supports sending to 1 address at a time! Sorry!"))
        return False
    gui.ElectrumGui.gui.jump_to_send_with_pay_to(addys[0])
    return True

def show_new_edit_contact(contact, parentvc, onEdit = None, title = None) -> ObjCInstance:
    nav = NSBundle.mainBundle.loadNibNamed_owner_options_("NewContact", None, None)[0]
    vc = nav.viewControllers[0]
    if contact:
        if isinstance(contact, ContactsEntry):
            pass
        if isinstance(contact, (tuple,list)) and len(contact) >= 2 and isinstance(contact[1], Address) and isinstance(contact[0], str):
            contact = ContactsEntry(contact[0], contact[1], contact[1].to_ui_string())
        elif isinstance(contact, Address):
            contact = ContactsEntry('', contact, contact.to_ui_string())
        else:
            raise ValueError('First parameter to show_new_edit_contact must be either a ContactsEntry, a tuple, or an Address!')
        utils.nspy_put_byname(vc, contact, 'edit_contact')
    if title:
        utils.nspy_put_byname(vc, title, 'title_override')

    def onOk(entry : ContactsEntry) -> None:
        #print ("parent onOK called...")
        if entry is not None:
            oldEntry = utils.nspy_get_byname(vc, 'old_contact')
            if oldEntry:
                delete_contact(oldEntry, False)
            add_contact(entry)
            _Updated()
            if callable(onEdit):
                onEdit(entry)
    utils.add_callback(vc, 'on_ok', onOk)
    parentvc.presentViewController_animated_completion_(nav, True, None)

def PushNewContactDetailVC(contact : ContactsEntry, navController : ObjCInstance) -> ObjCInstance:
    vc = ContactDetailVC.new().autorelease()
    _SetContact(vc, contact)
    navController.pushViewController_animated_(vc, True)
    return vc

def show_contact_options_actionsheet(contact : ContactsEntry, vc : ObjCInstance, view : ObjCInstance, navBackOnDelete = False, onEdit = None) -> None:
    #print ("On Options But")
    try:
        parent = gui.ElectrumGui.gui
        def on_block_explorer() -> None:
            parent.view_on_block_explorer(contact.address, 'addr')
        def on_pay_to() -> None:
            pay_to([contact.address_str])
        def on_cpy() -> None:
            parent.copy_to_clipboard(contact.address_str, 'Address')
            print ("copied to clipboard =", contact.address_str)
        def on_edit() -> None:
            show_new_edit_contact(contact, vc, onEdit = onEdit)
        def on_delete() -> None:
            def doDelete() -> None:
                if delete_contact(contact):
                    _Updated()
                if navBackOnDelete and vc.navigationController:
                    vc.navigationController.popViewControllerAnimated_(True)
                #utils.show_notification(message = _("Contact deleted."))
            parent.question(title=_("Confirm Delete"),
                            message=_("Are you sure you wish to delete this contact?"),
                            onOk=doDelete, vc=vc, destructive = True, okButTitle = _('Delete'))

        actions = [
                [ _('Cancel') ],
                [ _("Copy Address"), on_cpy ],
                [ _("Edit Contact"), on_edit],
                [ _("Pay to"), on_pay_to ],
                [ _("View on block explorer"), on_block_explorer ],
                [ _("Delete"), on_delete ],
            ]

        if parent.wallet.is_watching_only():
            actions.pop(3)

        if isinstance(vc, ContactDetailVC):
            actions.insert(2, [ _('Share/Save QR...'), lambda: vc.onQRImgTap() ])

        utils.show_alert(
            vc = vc,
            title = contact.name,#_("Options"),
            message = contact.address_str,
            actions = actions,
            cancel = _('Cancel'),
            destructive = _('Delete'),
            style = UIAlertControllerStyleActionSheet,
            ipadAnchor =  view.convertRect_toView_(view.bounds, vc.view) if isinstance(view, UIView) else view
        )
        #print ("address =", entry.address_str)
    except:
        utils.NSLog("*** WARNING: Exception during contacts.py 'show_contact_options_actionsheet': %s",str(sys.exc_info()[1]))
