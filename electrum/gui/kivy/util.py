from kivy.utils import get_color_from_hex


def address_colors(wallet, addr):
    """
    Chooses the appropriate text color and background color to 
    mark receiving, change and billing addresses.

    Returns: color, background_color
    """
    
    # modified colors (textcolor, background_color) from electrum/gui/qt/util.py
    GREEN = ("#000000", "#8af296")
    YELLOW = ("#000000", "#ffff00")
    BLUE = ("#000000", "#8cb3f2")
    DEFAULT = ('#ffffff', '#4c4c4c')

    colors = DEFAULT
    if wallet.is_mine(addr):
        colors = YELLOW if wallet.is_change(addr) else GREEN
    elif wallet.is_billing_address(addr):
        colors = BLUE
    return (get_color_from_hex(color) for color in colors)
