# TODO: Remove this when it is unlikely to encounter Qt5 installations that are
# missing QtMultimedia
def warn_unless_can_import_qrreader(parent):
    try:
        from .qrreader import QrReaderCameraDialog
    except ModuleNotFoundError as e:
        parent.show_error(
            "QR reader failed to load. This often happens if you are using"
            + " an old version of Qt5. \n\nDetailed error: " + str(e),
            title = "QR reader disabled")
        return False
    return True

