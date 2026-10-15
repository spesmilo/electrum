import math
import re

from time import time
from typing import Tuple

from electrum.i18n import _


# return delay in msec when expiry time string should be updated
# returns 0 when expired or expires > 1 day away (no updates needed)
def status_update_timer_interval(exp):
    # very roughly according to util.age
    exp_in = int(exp - time())
    exp_in_min = int(exp_in/60)

    interval = 0
    if exp_in < 0:
        interval = 0
    elif exp_in_min < 2:
        interval = 1000
    elif exp_in_min < 90:
        interval = 1000 * 60
    elif exp_in_min < 1440:
        interval = 1000 * 60 * 60

    return interval


# TODO: copied from qt password_dialog.py, move to common code
def check_password_strength(password: str) -> Tuple[int, str]:
    """Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong"""
    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*(n + caps + num + extra)/20
    password_strength = {0: _('Weak'), 1: _('Medium'), 2: _('Strong'), 3: _('Very Strong')}
    return min(3, int(score)), password_strength[min(3, int(score))]
