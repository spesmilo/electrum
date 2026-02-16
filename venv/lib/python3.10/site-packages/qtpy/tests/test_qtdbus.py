import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtdbus():
    """Test the qtpy.QtDBus namespace"""
    QtDBus = pytest_importorskip("qtpy.QtDBus")

    assert QtDBus.QDBusAbstractAdaptor is not None
    assert QtDBus.QDBusAbstractInterface is not None
    assert QtDBus.QDBusArgument is not None
    assert QtDBus.QDBusConnection is not None
