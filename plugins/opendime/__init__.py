from electrum.i18n import _

fullname = 'Opendime Helper'

description = _('Simplify and streamline access to connected Opendime devices')

available_for = ['qt', ]

# NOTE: We don't **require** it, but if libusb is available to use, then we can
# perform more checks into the authenticity of the attached Opendime.
#
#       pip install PyUSB
#
#       >>> import usb
#       >>> usb.core.find(idVendor=0xd13e)
#       <DEVICE ID d13e:0100 on Bus 020 Address 027>
#
#
