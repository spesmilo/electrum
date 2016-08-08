import os, sys, json
from electrum.i18n import _
from electrum.bitcoin import verify_message

from base64 import b64decode, urlsafe_b64decode
from hashlib import md5

try:
    B2A = lambda x:x
except NameError: # Py3
    B2A = lambda x: str(x, 'ascii')


# We want to use libusb to verify Opendime units by
# sending them unknowable messages to sign, but don't want to
# make libusb a requirement for this plugin, because
# it can be hard to install, and for the non-paranoid
# it adds no value.
try:
    import usb.core

    has_libusb = True
except ImportError:
    has_libusb = False

# "psutils" is the best way to find Opendime's
# once they are connected and mounted by the
# operating system. It's also cross-platform.
# However, there are other simple ways to
# find opendime units, so we can fallback.
try:
    import psutil

    has_psutil = True
except ImportError:
    has_psutil = False

# List of checksums and known versions.
#
# Can be updated from https://opendime.com/versions or https://opendime.com/versions.csv
#
KNOWN_VERSIONS = {
    '1.1.0': '16c11de6269b47689dcad2406677c489bdfbe166c93f78944884952b37a0d902',
    '1.0.0': 'd5f0a97f8d9683c08a10497eafbd443c42c322c132c637a6e477dccf1f286043',
}

# This code is taken from v1.1.0 of
#   pycode.zip/trust_me.py
# as shipped on Opendime units, with some minor changes.
#
def lowlevel_verify(root_path, expect_addr, version, rounds=2):

    def fail(msg):
        raise AssertionError("Verify failed: " + msg)

    # this requires: "pip install PyUSB" and a working libusb library
    try:
        import usb, usb.core
    except ImportError:
        fail("additional tests are possible with libusb and PyUSB installed")

    import json, string, random, time
    from base64 import b64encode

    variables = json.load(open(os.path.join(root_path, 'advanced', 'variables.json')))

    class dev(object):
        def __init__(self, sn):
            self.dev = usb.core.find(idVendor=0xd13e, custom_match=lambda d:d.serial_number==sn)
            assert self.dev, "Was not able to find USB device!"

        def read(self, idx):
            return self.dev.ctrl_transfer(bmRequestType=0xc0, bRequest=0, wValue=idx,
                                    data_or_wLength=500).tostring()

        def write(self, cmd, data):
            self.dev.ctrl_transfer(bmRequestType=0x40, bRequest=0, wValue=ord(cmd), data_or_wLength=data)

    try:
        u = dev(variables['sn'])
        assert u.dev.serial_number == variables['sn'], "Serial number mismatch"
    except AssertionError:
        fail("Could not find device over low-level SUB")

    try:
        # version 1.0.0 will fail here
        addr = B2A(u.read(3))
    except:
        if version == '1.0.0':
            #print("  - old version cannot do more checks")
            return

    try:
        assert addr == variables['ad'].strip(), "Payment address mismatch"
        assert addr == expect_addr, "JSON vs address.txt mismatch"
    except AssertionError:
        fail('''\
Low level USB details do not match the values observed at the filesystem level!''')

    #print("  - read-back over USB EP0 correct")

    for i in range(rounds):
        msg = ''.join(random.sample(string.printable[:-6], 32))
        u.write('m', msg)

        for retry in range(1000):
            try:
                sig = B2A(u.read(4))
                break
            except usb.core.USBError:
                time.sleep(.010)

        ok = verify_message(addr, sig, msg)
        if not ok:
            fail("Incorrect signature on verification message!")

        #print("  - (#%d) signed message ok: %s ~ %s" % (i+1, msg[0:8], msg[-8:]))



class AttachedOpendime(object):
    '''
        Represents an Opendime unit attached to this sytem.

        Many useful properties on this object:

            is_new - needs entropy/hasn't picked address yet
            is_sealed - private key not yet revealed
            address - deposit address for this opendime
            serial - USB-level serial number, if known
            version - dotted-decimal: 1.1.0 and so on
            build - dict of build info (more detailed)
            privkey - private key iff unsealed
    '''

    def __init__(self, root_path):
        '''
            Create new instance; loads some key values.
        '''
        self.root_path = root_path

        self.verify_level = 0

        # regardless of mode, version file always there
        fname = self.make_fname('advanced', 'version.txt')
        if not fname:
            raise ValueError("Not found: " + root_path)

        parts = file(fname, 'rt').read().strip().split(' ')
        self.version = parts[0]
        self.build = dict(i.split('=',1) for i in parts[1:])

        fname = self.make_fname('advanced', 'variables.json')
        if fname:
            self.is_new = False
            self.variables = json.load(file(fname))
        else:
            self.is_new = True
            self.variables = {}

        # should usally follow up with: self.verify()

    def make_fname(self, *path_parts):
        fname = os.path.join(self.root_path, *path_parts)
        return fname if os.path.isfile(fname) else None


    @classmethod
    def probe_opendime(cls, path):
        # does this look like an opendime drive rooted at path?
        v = os.path.join(path, 'advanced', 'version.txt')
        logo = os.path.join(path, 'support', 'opendime.png')
        return os.path.isfile(v) and os.path.isfile(logo)

    @classmethod
    def get_mountpoints(cls):
        '''
            Get a list of possible places that Opendime might have gotten mounted.
        '''
        if has_psutil:
            # PREFERED approach:
            # - with "psutil" can just enum every mounted disk. Very cross-platform.
            # - would like to check p.fstype but not clear what values it might
            #   take on... 'msdos' on Mac, but maybe 'fat12' on Windows?
            return [p.mountpoint for p in psutil.disk_partitions() if
                        p.fstype.lower() not in ('ntfs', 'hfs')]

        # fallback code here... for when psutils not installed

        if os.name == 'posix':
            # linux might mount under /media/<username>/ or /media/usb*/
            # macos will be /Volumes
            # freebsd, hard to know.
            homes = ['/Volumes', '/media', '/mnt']

            dirs = []
            for home in homes:
                try:
                    here = os.listdir(home)
                except:
                    continue

                for dn in here:
                    fp = home + '/' + dn
                    if os.path.isdir(fp):
                        dirs.append(fp)

            return dirs

        elif sys.platform.startswith('win'):
            # Just a random assortment of drive letters?
            # XXX untested.
            return ['\\\\%s\\'%chr(i+65) for i in range(26)]

        else:
            raise RuntimeError("No way to find USB drives on this system; " \
                                    "please:\n\t pip install psutil")

    @classmethod
    def find(cls, mounts=None):
        '''
            Find all Opendime devices currently attached to this system.
            OS specific, but only barely...
        '''

        if mounts is None:
            mounts = cls.get_mountpoints()

        return [p for p in mounts if cls.probe_opendime(p)]

    def verify_wrapped(self):
        # wrapper
        try:
            self.verify()
            self.problem = None
        except AssertionError as e:
            self.verify_level = 0
            self.problem = str(e)

    def verify(self):
        '''
            Check this is an authentic Opendime, which knows the right priv key.

            Raises an AssertionError on any issue; all of which indicate failure
            and untrustworthy unit.

            Quality of verification is shown in self.verify_level as 1 through 10 or so.
        '''
        if self.version in KNOWN_VERSIONS:
            chk = self.get_checksum()
            assert KNOWN_VERSIONS[self.version] == chk, "Checksum wrong for version!?"
            self.verify_level += 1

        # Test the filesystem layout. Powerful.
        if hasattr(os, 'statvfs'):
            g = os.statvfs(self.root_path)
            try:
                assert g.f_bsize == 131072
                assert g.f_frsize == 512
                assert g.f_blocks in (2847, 2880)
            except AssertionError:
                raise AssertionError("os.statvfs didn't show correct disk geometry")

            self.verify_level += 1

        if self.is_new:
            # Limited checking possible w/o a private key, but stakes
            # are at zero anyway?
            return

        # the hard stuff ... signed messages. There are 3 available.
        for item in range(3):
            if item == 0:
                msg, addr, signature, code = self.variables['va'].strip().split('|')
                signature = urlsafe_b64decode((signature+'====').encode('utf8'))
            elif item == 1:
                fn = self.make_fname('advanced', 'verify2.txt')
                msg, addr, signature = [i.strip() for i in file(fn).readlines()[0:3]]
                signature = b64decode(signature.encode('utf8'))
            elif item == 2:
                fn = self.make_fname('advanced', 'verify.txt')
                lines = filter(None, (i.strip() for i in file(fn).readlines()
                                                if not i.startswith('-----')))
                msg = '\r\n'.join(lines[0:-2])
                addr = lines[-2]
                signature = lines[-1]
                signature = b64decode(signature.encode('utf8'))

            assert addr == self.address, "Signature was copied from some other Opendime!"

            ok = verify_message(addr, signature, msg)
            assert ok, "Signature did not verify (case %d)." % item

            self.verify_level += 1

        # if we can do the real low-level checks, do them because they
        # are the ultimate test
        if has_libusb:
            lowlevel_verify(self.root_path, self.address, self.version)
            self.verify_level += 5


    @property
    def is_sealed(self):
        if self.is_new: return True
        return self.variables['pk'][0] != '5'

    @property
    def address(self):
        return self.variables.get('ad', None).strip()

    @property
    def serial(self):
        if 'sn' in self.variables:
            return self.variables['sn'].strip()

        # New units don't report their serial numbers (yet!!). Make one.
        # This is on our list to fix in the next version of firmware.

        return md5(self.root_path).hexdigest()

    @property
    def privkey(self):
        if not self.is_sealed:
            return self.variables['pk'].strip()
        else:
            raise RuntimeError("Opendime is sealed")

    def get_checksum(self):
        fn = self.make_fname('advanced', 'checksum.txt')
        return file(fn).read().strip() if fn else None

    def __repr__(self):
        return "<OPENDIME @ %s>" % self.root_path

    def initalize(self, entropy):
        '''
            Take a factory-fresh unit and load with entropy. Will eject itself.
        '''
        assert self.is_new
        assert len(entropy) >= 256*1024, "Need at least 256k of data"

        fn = os.path.join(self.root_path, 'whatever.bin')
        file(fn, 'wb').write(entropy)


def test_macos():

    ods = AttachedOpendime.find()
    print 'ods = %r' % ods

    for pn in ods:
        a = AttachedOpendime(pn)
        a.verify()
        print
        print 'repr(a) = %r' % a
        print 'is_sealed = %r' % a.is_sealed
        print 'is_new = %r' % a.is_new
        print 'verify_level = %r' % a.verify_level
        print 'address = %r' % a.address
        print 'serial = %r' % a.serial
        print 'version = %r' % a.version
        print 'build = %r' % a.build
        print 'chk = %r' % a.get_checksum()
        if not a.is_sealed:
            print 'privkey = %r' % a.privkey


if __name__ == '__main__':
    test_macos()

