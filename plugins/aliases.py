import re
import platform
from decimal import Decimal

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum_gui.qrcodewidget import QRCodeWidget
from electrum_gui import bmp, pyqrnative
from electrum_gui.i18n import _


ALIAS_REGEXP = '^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$'    


config = {}

def get_info():
    return 'Aliases', _('Retrieve aliases using http.')

def init(self):
    global config
    config = self.config
    self.aliases               = config.get('aliases', {})            # aliases for addresses
    self.authorities           = config.get('authorities', {})        # trusted addresses
    self.receipts              = config.get('receipts',{})            # signed URIs
    do_enable(self, is_enabled())

def is_enabled():
    return config.get('use_aliases') is True

def is_available():
    return True


def toggle(gui):
    enabled = not is_enabled()
    config.set_key('use_aliases', enabled, True)
    do_enable(gui, enabled)
    return enabled


def do_enable(gui, enabled):
    if enabled:
        gui.set_hook('timer_actions', timer_actions)
        gui.set_hook('set_url', set_url_hook)
        gui.set_hook('update_contacts_tab', update_contacts_tab_hook)
        gui.set_hook('update_completions', update_completions_hook)
        gui.set_hook('create_contact_menu', create_contact_menu_hook)
    else:
        gui.unset_hook('timer_actions', timer_actions)
        gui.unset_hook('set_url', set_url_hook)
        gui.unset_hook('update_contacts_tab', update_contacts_tab_hook)
        gui.unset_hook('update_completions', update_completions_hook)
        gui.unset_hook('create_contact_menu', create_contact_menu_hook)


def timer_actions(self):
    if self.payto_e.hasFocus():
        return
    r = unicode( self.payto_e.text() )
    if r != self.previous_payto_e:
        self.previous_payto_e = r
        r = r.strip()
        if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', r):
            try:
                to_address = get_alias(self, r, True, self.show_message, self.question)
            except:
                return
            if to_address:
                s = r + '  <' + to_address + '>'
                self.payto_e.setText(s)


def get_alias(self, alias, interactive = False, show_message=None, question = None):
    try:
        target, signing_address, auth_name = read_alias(self, alias)
    except BaseException, e:
        # raise exception if verify fails (verify the chain)
        if interactive:
            show_message("Alias error: " + str(e))
        return

    print target, signing_address, auth_name

    if auth_name is None:
        a = self.aliases.get(alias)
        if not a:
            msg = "Warning: the alias '%s' is self-signed.\nThe signing address is %s.\n\nDo you want to add this alias to your list of contacts?"%(alias,signing_address)
            if interactive and question( msg ):
                self.aliases[alias] = (signing_address, target)
            else:
                target = None
        else:
            if signing_address != a[0]:
                msg = "Warning: the key of alias '%s' has changed since your last visit! It is possible that someone is trying to do something nasty!!!\nDo you accept to change your trusted key?"%alias
                if interactive and question( msg ):
                    self.aliases[alias] = (signing_address, target)
                else:
                    target = None
    else:
        if signing_address not in self.authorities.keys():
            msg = "The alias: '%s' links to %s\n\nWarning: this alias was signed by an unknown key.\nSigning authority: %s\nSigning address: %s\n\nDo you want to add this key to your list of trusted keys?"%(alias,target,auth_name,signing_address)
            if interactive and question( msg ):
                self.authorities[signing_address] = auth_name
            else:
                target = None

    if target:
        self.aliases[alias] = (signing_address, target)
            
    return target



def read_alias(self, alias):
    import urllib

    m1 = re.match('([\w\-\.]+)@((\w[\w\-]+\.)+[\w\-]+)', alias)
    m2 = re.match('((\w[\w\-]+\.)+[\w\-]+)', alias)
    if m1:
        url = 'https://' + m1.group(2) + '/bitcoin.id/' + m1.group(1) 
    elif m2:
        url = 'https://' + alias + '/bitcoin.id'
    else:
        return ''
    try:
        lines = urllib.urlopen(url).readlines()
    except:
        return ''

    # line 0
    line = lines[0].strip().split(':')
    if len(line) == 1:
        auth_name = None
        target = signing_addr = line[0]
    else:
        target, auth_name, signing_addr, signature = line
        msg = "alias:%s:%s:%s"%(alias,target,auth_name)
        print msg, signature
        EC_KEY.verify_message(signing_addr, signature, msg)
        
    # other lines are signed updates
    for line in lines[1:]:
        line = line.strip()
        if not line: continue
        line = line.split(':')
        previous = target
        print repr(line)
        target, signature = line
        EC_KEY.verify_message(previous, signature, "alias:%s:%s"%(alias,target))

    if not is_valid(target):
        raise ValueError("Invalid bitcoin address")

    return target, signing_addr, auth_name


def set_url_hook(self, url, show_message, question):
    payto, amount, label, message, signature, identity, url = util.parse_url(url)
    if signature:
        if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', identity):
            signing_address = get_alias(identity, True, show_message, question)
        elif is_valid(identity):
            signing_address = identity
        else:
            signing_address = None
        if not signing_address:
            return
        try:
            EC_KEY.verify_message(signing_address, signature, url )
            self.receipt = (signing_address, signature, url)
        except:
            show_message('Warning: the URI contains a bad signature.\nThe identity of the recipient cannot be verified.')
            address = amount = label = identity = message = ''

    if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', address):
        payto_address = get_alias(address, True, show_message, question)
        if payto_address:
            address = address + ' <' + payto_address + '>'

    return address, amount, label, message, signature, identity, url



def update_contacts_tab_hook(self, l):
    alias_targets = []
    for alias, v in self.aliases.items():
        s, target = v
        alias_targets.append(target)
        item = QTreeWidgetItem( [ target, alias, '-'] )
        item.setBackgroundColor(0, QColor('lightgray'))
        l.insertTopLevelItem(0,item)
        item.setData(0,32,False)
        item.setData(0,33,alias + ' <' + target + '>')



def update_completions_hook(self, l):
    l[:] = l + self.aliases.keys()


def create_contact_menu_hook(self, menu, item):
    label = unicode(item.text(1))
    if label in self.aliases.keys():
        addr = unicode(item.text(0))
        label = unicode(item.text(1))
        menu.addAction(_("View alias details"), lambda: show_contact_details(self, label))
        menu.addAction(_("Delete alias"), lambda: delete_alias(self, label))


def show_contact_details(self, m):
    a = self.aliases.get(m)
    if a:
        if a[0] in self.authorities.keys():
            s = self.authorities.get(a[0])
        else:
            s = "self-signed"
        msg = _('Alias:')+' '+ m + '\n'+_('Target address:')+' '+ a[1] + '\n\n'+_('Signed by:')+' ' + s + '\n'+_('Signing address:')+' ' + a[0]
        QMessageBox.information(self, 'Alias', msg, 'OK')


def delete_alias(self, x):
    if self.question(_("Do you want to remove")+" %s "%x +_("from your list of contacts?")):
        if x in self.aliases:
            self.aliases.pop(x)
            self.update_history_tab()
            self.update_contacts_tab()
            self.update_completions()
