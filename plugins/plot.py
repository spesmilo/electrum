from PyQt4.QtGui import *
from electrum_grs.plugins import BasePlugin, hook
from electrum_grs.i18n import _


import datetime
from electrum_grs.util import format_satoshis


try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as md
    from matplotlib.patches import Ellipse
    from matplotlib.offsetbox import AnchoredOffsetbox, TextArea, DrawingArea, HPacker
    flag_matlib=True
except:
    flag_matlib=False





class Plugin(BasePlugin):


    def fullname(self):
        return 'Plot History'

    def description(self):
        return '%s\n%s' % (_("Ability to plot transaction history in graphical mode."), _("Warning: Requires matplotlib library."))

    def is_available(self):
        if flag_matlib:
            return True
        else:
            return False

    @hook
    def init_qt(self, gui):
        self.win = gui.main_window

    @hook
    def export_history_dialog(self, d,hbox):
        self.wallet = d.wallet

        history = self.wallet.get_tx_history()

        if len(history) > 0:
            b = QPushButton(_("Preview plot"))
            hbox.addWidget(b)
            b.clicked.connect(lambda: self.do_plot(self.wallet))
        else:
            b = QPushButton(_("No history to plot"))
            hbox.addWidget(b)



    def do_plot(self,wallet):
        history = wallet.get_tx_history()
        balance_Val=[]
        fee_val=[]
        value_val=[]
        datenums=[]
        unknown_trans=0
        pending_trans=0
        counter_trans=0
        for item in history:
            tx_hash, confirmations, is_mine, value, fee, balance, timestamp = item
            if confirmations:
                if timestamp is not None:
                    try:
                        datenums.append(md.date2num(datetime.datetime.fromtimestamp(timestamp)))
                        balance_string = format_satoshis(balance, False)
                        balance_Val.append(float((format_satoshis(balance,False)))*1000.0)
                    except [RuntimeError, TypeError, NameError] as reason:
                        unknown_trans=unknown_trans+1
                        pass
                else:
                    unknown_trans=unknown_trans+1
            else:
                pending_trans=pending_trans+1

            if value is not None:
                value_string = format_satoshis(value, True)
                value_val.append(float(value_string)*1000.0)
            else:
                value_string = '--'

            if fee is not None:
                fee_string = format_satoshis(fee, True)
                fee_val.append(float(fee_string))
            else:
                fee_string = '0'

            if tx_hash:
                label, is_default_label = wallet.get_label(tx_hash)
                label = label.encode('utf-8')
            else:
                label = ""


        f, axarr = plt.subplots(2, sharex=True)

        plt.subplots_adjust(bottom=0.2)
        plt.xticks( rotation=25 )
        ax=plt.gca()
        x=19
        test11="Unknown transactions =  "+str(unknown_trans)+" Pending transactions =  "+str(pending_trans)+" ."
        box1 = TextArea(" Test : Number of pending transactions", textprops=dict(color="k"))
        box1.set_text(test11)


        box = HPacker(children=[box1],
            align="center",
            pad=0.1, sep=15)

        anchored_box = AnchoredOffsetbox(loc=3,
            child=box, pad=0.5,
            frameon=True,
            bbox_to_anchor=(0.5, 1.02),
            bbox_transform=ax.transAxes,
            borderpad=0.5,
        )


        ax.add_artist(anchored_box)


        plt.ylabel('mBTC')
        plt.xlabel('Dates')
        xfmt = md.DateFormatter('%Y-%m-%d')
        ax.xaxis.set_major_formatter(xfmt)


        axarr[0].plot(datenums,balance_Val,marker='o',linestyle='-',color='blue',label='Balance')
        axarr[0].legend(loc='upper left')
        axarr[0].set_title('History Transactions')


        xfmt = md.DateFormatter('%Y-%m-%d')
        ax.xaxis.set_major_formatter(xfmt)
        axarr[1].plot(datenums,fee_val,marker='o',linestyle='-',color='red',label='Fee')
        axarr[1].plot(datenums,value_val,marker='o',linestyle='-',color='green',label='Value')




        axarr[1].legend(loc='upper left')
     #   plt.annotate('unknown transaction = %d \n pending transactions = %d' %(unknown_trans,pending_trans),xy=(0.7,0.05),xycoords='axes fraction',size=12)
        plt.show()
