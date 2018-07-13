import datetime
from collections import defaultdict

import matplotlib
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as md

from .i18n import _
from .bitcoin import COIN


class NothingToPlotException(Exception):
    def __str__(self):
        return _("Nothing to plot.")


def plot_history(history):
    if len(history) == 0:
        raise NothingToPlotException()
    hist_in = defaultdict(int)
    hist_out = defaultdict(int)
    for item in history:
        if not item['confirmations']:
            continue
        if item['timestamp'] is None:
            continue
        value = item['value'].value/COIN
        date = item['date']
        datenum = int(md.date2num(datetime.date(date.year, date.month, 1)))
        if value > 0:
            hist_in[datenum] += value
        else:
            hist_out[datenum] -= value

    f, axarr = plt.subplots(2, sharex=True)
    plt.subplots_adjust(bottom=0.2)
    plt.xticks( rotation=25 )
    ax = plt.gca()
    plt.ylabel('LTC')
    plt.xlabel('Month')
    xfmt = md.DateFormatter('%Y-%m-%d')
    ax.xaxis.set_major_formatter(xfmt)
    axarr[0].set_title('Monthly Volume')
    xfmt = md.DateFormatter('%Y-%m')
    ax.xaxis.set_major_formatter(xfmt)
    width = 20

    r1 = None
    r2 = None
    dates_values = list(zip(*sorted(hist_in.items())))
    if dates_values and len(dates_values) == 2:
        dates, values = dates_values
        r1 = axarr[0].bar(dates, values, width, label='incoming')
        axarr[0].legend(loc='upper left')
    dates_values = list(zip(*sorted(hist_out.items())))
    if dates_values and len(dates_values) == 2:
        dates, values = dates_values
        r2 = axarr[1].bar(dates, values, width, color='r', label='outgoing')
        axarr[1].legend(loc='upper left')
    if r1 is None and r2 is None:
        raise NothingToPlotException()
    return plt
