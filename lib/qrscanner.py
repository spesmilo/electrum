import os

try:
    import zbar
except ImportError:
    zbar = None


def scan_qr(config):
    if not zbar:
        return
    device = config.get("video_device", "default")
    if device == 'default':
        device = ''
    proc = zbar.Processor()
    proc.init(video_device=device)
    proc.visible = True
    while True:
        try:
            proc.process_one()
        except Exception:
            # User closed the preview window
            return {}
        for r in proc.results:
            if str(r.type) != 'QRCODE':
                continue
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
