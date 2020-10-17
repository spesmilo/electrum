from PyQt5.QtGui import *
from .i18n import _


import datetime
from collections import defaultdict
from .bitcoin import COIN

import matplotlib
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as md
from matplotlib.patches import Ellipse
from matplotlib.offsetbox import AnchoredOffsetbox, TextArea, DrawingArea, HPacker


def plot_history(wallet, history):
    hist_in = defaultdict(int)
    hist_out = defaultdict(int)
    for item in history:
        tx_hash, height, confirmations, timestamp, value, balance = item
        if not confirmations:
            continue
        if timestamp is None:
            continue
        value = value*1./COIN
        date = datetime.datetime.fromtimestamp(timestamp)
        datenum = int(md.date2num(datetime.date(date.year, date.month, 1)))
        if value > 0:
            hist_in[datenum] += value
        else:
            hist_out[datenum] -= value

    f, axarr = plt.subplots(2, sharex=True)
    plt.subplots_adjust(bottom=0.2)
    plt.xticks( rotation=25 )
    ax = plt.gca()
    plt.ylabel('BCH')
    plt.xlabel('Month')
    xfmt = md.DateFormatter('%Y-%m-%d')
    ax.xaxis.set_major_formatter(xfmt)
    axarr[0].set_title('Monthly Volume')
    xfmt = md.DateFormatter('%Y-%m')
    ax.xaxis.set_major_formatter(xfmt)
    width = 20
    dates, values = zip(*sorted(hist_in.items()))
    r1 = axarr[0].bar(dates, values, width, label='incoming')
    axarr[0].legend(loc='upper left')
    dates, values = zip(*sorted(hist_out.items()))
    r2 = axarr[1].bar(dates, values, width, color='r', label='outgoing')
    axarr[1].legend(loc='upper left')
    return plt
