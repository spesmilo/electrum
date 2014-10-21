import os
from i18n import _

try:
    import zbar
except ImportError:
    zbar = None

proc = None

def init(config):
    if not zbar:
        raise BaseException("\n".join([_("Cannot start QR scanner."),_("The zbar package is not available."),_("On Linux, try 'sudo apt-get install python-zbar'")]))
    device = config.get("video_device", "default")
    if device == 'default':
        device = ''
    global proc
    proc = zbar.Processor()
    proc.init(video_device=device)

def scan_qr(self):
    if not zbar:
        raise BaseException("\n".join([_("Cannot start QR scanner."),_("The zbar package is not available."),_("On Linux, try 'sudo apt-get install python-zbar'")]))
    if proc is None:
        raise BaseException("Start proc first")
    proc.visible = True
    while True:
        try:
            proc.process_one()
        except Exception:
            # User closed the preview window
            return ""
        for r in proc.results:
            if str(r.type) != 'QRCODE':
                continue
            # hiding the preview window stops the camera
            proc.visible = False
            return r.data

def _find_system_cameras():
    device_root = "/sys/class/video4linux"
    devices = {} # Name -> device
    if os.path.exists(device_root):
        for device in os.listdir(device_root):
            name = open(os.path.join(device_root, device, 'name')).read()
            name = name.strip('\n')
            devices[name] = os.path.join("/dev",device)
    return devices
