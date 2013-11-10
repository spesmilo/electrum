import re
import platform
from decimal import Decimal

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum import bmp, pyqrnative
from electrum.i18n import _

from electrum import util

ALIAS_REGEXP = '^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$'    



from electrum.plugins import BasePlugin

class Plugin(BasePlugin):

    def fullname(self): return 'Aliases'

    def description(self): return _('Retrieve aliases using http.')

    def init(self):
        self.aliases      = self.config.get('aliases', {})            # aliases for addresses
        self.authorities  = self.config.get('authorities', {})        # trusted addresses
        self.receipts     = self.config.get('receipts',{})            # signed URIs

    def is_available(self):
        return False

    def timer_actions(self):
        if self.gui.payto_e.hasFocus():
            return
        r = unicode( self.gui.payto_e.text() )
        if r != self.gui.previous_payto_e:
            self.gui.previous_payto_e = r
            r = r.strip()
            if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', r):
                try:
                    to_address = self.get_alias(r, True, self.gui.show_message, self.gui.question)
                except Exception:
                    return
                if to_address:
                    s = r + '  <' + to_address + '>'
                    self.gui.payto_e.setText(s)


    def get_alias(self, alias, interactive = False, show_message=None, question = None):
        try:
            target, signing_address, auth_name = read_alias(self, alias)
        except Exception as e:
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
        except Exception:
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


    def set_url(self, url, show_message, question):
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
            except Exception:
                show_message('Warning: the URI contains a bad signature.\nThe identity of the recipient cannot be verified.')
                address = amount = label = identity = message = ''

        if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', payto):
            payto_address = get_alias(payto, True, show_message, question)
            if payto_address:
                payto += ' <' + payto_address + '>'

        return payto, amount, label, message, signature, identity, url



    def update_contacts_tab(self, l):
        alias_targets = []
        for alias, v in self.aliases.items():
            s, target = v
            alias_targets.append(target)
            item = QTreeWidgetItem( [ target, alias, '-'] )
            item.setBackgroundColor(0, QColor('lightgray'))
            item.setData(0,32,False)
            item.setData(0,33,alias + ' <' + target + '>')
            l.insertTopLevelItem(0,item)


    def update_completions(self, l):
        l[:] = l + self.aliases.keys()


    def create_contact_menu(self, menu, item):
        label = unicode(item.text(1))
        if label in self.aliases.keys():
            addr = unicode(item.text(0))
            label = unicode(item.text(1))
            menu.addAction(_("View alias details"), lambda: self.show_contact_details(label))
            menu.addAction(_("Delete alias"), lambda: delete_alias(self, label))


    def show_contact_details(self, m):
        a = self.aliases.get(m)
        if a:
            if a[0] in self.authorities.keys():
                s = self.authorities.get(a[0])
            else:
                s = "self-signed"
            msg = _('Alias:')+' '+ m + '\n'+_('Target address:')+' '+ a[1] + '\n\n'+_('Signed by:')+' ' + s + '\n'+_('Signing address:')+' ' + a[0]
            QMessageBox.information(self.gui, 'Alias', msg, 'OK')


    def delete_alias(self, x):
        if self.gui.question(_("Do you want to remove")+" %s "%x +_("from your list of contacts?")):
            if x in self.aliases:
                self.aliases.pop(x)
                self.update_history_tab()
                self.update_contacts_tab()
                self.update_completions()
