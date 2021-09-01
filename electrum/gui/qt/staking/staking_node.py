#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

from typing import TYPE_CHECKING

from PyQt5.QtCore import (Qt, QModelIndex, QVariant)
from PyQt5.QtGui import QFont, QBrush, QColor

from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import (format_time)
from .staking_sort_model import StakingColumns
from ..custom_model import CustomNode
from ..history_list import TX_ICONS
from ..util import (read_QIcon, MONOSPACE_FONT)

if TYPE_CHECKING:
    pass

_logger = get_logger(__name__)


class StakingNode(CustomNode):

    def get_data_for_role(self, index: QModelIndex, role: Qt.ItemDataRole) -> QVariant:
        # note: this method is performance-critical.
        # it is called a lot, and so must run extremely fast.
        assert index.isValid()
        col = index.column()
        window = self.model.parent
        tx_item = self.get_data()
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        if is_lightning:
            status = 0
            if timestamp is None:
                status_str = _('unconfirmed')
            else:
                status_str = format_time(int(timestamp))
        else:
            tx_hash = tx_item['txid']
            conf = tx_item['confirmations']
            try:
                status, status_str = self.model.tx_status_cache[tx_hash]
            except KeyError:
                tx_mined_info = self.model.tx_mined_info_from_tx_item(tx_item)
                status, status_str = window.wallet.get_tx_status(tx_hash, tx_mined_info)

        if role == Qt.UserRole:
            # for sorting
            d = {
                StakingColumns.STATUS:
                # respect sort order of self.transactions (wallet.get_full_history)
                    -index.row(),
                StakingColumns.DESCRIPTION:
                    tx_item['label'] if 'label' in tx_item else None,
                StakingColumns.AMOUNT:
                    (tx_item['bc_value'].value if 'bc_value' in tx_item else 0) \
                    + (tx_item['ln_value'].value if 'ln_value' in tx_item else 0),
                StakingColumns.BALANCE:
                    (tx_item['balance'].value if 'balance' in tx_item else 0),
                StakingColumns.FIAT_VALUE:
                    tx_item['fiat_value'].value if 'fiat_value' in tx_item else None,
                StakingColumns.FIAT_ACQ_PRICE:
                    tx_item['acquisition_price'].value if 'acquisition_price' in tx_item else None,
                StakingColumns.FIAT_CAP_GAINS:
                    tx_item['capital_gain'].value if 'capital_gain' in tx_item else None,
                StakingColumns.TXID: tx_hash if not is_lightning else None,
            }
            return QVariant(d[col])
        if role not in (Qt.DisplayRole, Qt.EditRole):
            if col == StakingColumns.STATUS and role == Qt.DecorationRole:
                icon = "lightning" if is_lightning else TX_ICONS[status]
                return QVariant(read_QIcon(icon))
            elif col == StakingColumns.STATUS and role == Qt.ToolTipRole:
                if is_lightning:
                    msg = 'lightning transaction'
                else:  # on-chain
                    if tx_item['height'] == TX_HEIGHT_LOCAL:
                        # note: should we also explain double-spends?
                        msg = _("This transaction is only available on your local machine.\n"
                                "The currently connected server does not know about it.\n"
                                "You can either broadcast it now, or simply remove it.")
                    else:
                        msg = str(conf) + _(" confirmation" + ("s" if conf != 1 else ""))
                return QVariant(msg)
            elif col > StakingColumns.DESCRIPTION and role == Qt.TextAlignmentRole:
                return QVariant(int(Qt.AlignRight | Qt.AlignVCenter))
            elif col > StakingColumns.DESCRIPTION and role == Qt.FontRole:
                monospace_font = QFont(MONOSPACE_FONT)
                return QVariant(monospace_font)
            # elif col == StakingColumns.DESCRIPTION and role == Qt.DecorationRole and not is_lightning\
            #        and self.parent.wallet.invoices.paid.get(tx_hash):
            #    return QVariant(read_QIcon("seal"))
            elif col in (StakingColumns.DESCRIPTION, StakingColumns.AMOUNT) \
                    and role == Qt.ForegroundRole and tx_item['value'].value < 0:
                red_brush = QBrush(QColor("#BC1E1E"))
                return QVariant(red_brush)
            elif col == StakingColumns.FIAT_VALUE and role == Qt.ForegroundRole \
                    and not tx_item.get('fiat_default') and tx_item.get('fiat_value') is not None:
                blue_brush = QBrush(QColor("#1E1EFF"))
                return QVariant(blue_brush)
            return QVariant()
        if col == StakingColumns.STATUS:
            return QVariant(status_str)
        elif col == StakingColumns.DESCRIPTION and 'label' in tx_item:
            return QVariant(tx_item['label'])
        elif col == StakingColumns.AMOUNT:
            bc_value = tx_item['bc_value'].value if 'bc_value' in tx_item else 0
            ln_value = tx_item['ln_value'].value if 'ln_value' in tx_item else 0
            value = bc_value + ln_value
            v_str = window.format_amount(value, is_diff=True, whitespaces=True)
            return QVariant(v_str)
        elif col == StakingColumns.BALANCE:
            balance = tx_item['balance'].value
            balance_str = window.format_amount(balance, whitespaces=True)
            return QVariant(balance_str)
        elif col == StakingColumns.FIAT_VALUE and 'fiat_value' in tx_item:
            value_str = window.fx.format_fiat(tx_item['fiat_value'].value)
            return QVariant(value_str)
        elif col == StakingColumns.FIAT_ACQ_PRICE and \
                tx_item['value'].value < 0 and 'acquisition_price' in tx_item:
            # fixme: should use is_mine
            acq = tx_item['acquisition_price'].value
            return QVariant(window.fx.format_fiat(acq))
        elif col == StakingColumns.FIAT_CAP_GAINS and 'capital_gain' in tx_item:
            cg = tx_item['capital_gain'].value
            return QVariant(window.fx.format_fiat(cg))
        elif col == StakingColumns.TXID:
            return QVariant(tx_hash) if not is_lightning else QVariant('')
        return QVariant()
