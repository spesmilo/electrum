import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtwinextras():
    QtX11Extras = pytest_importorskip("qtpy.QtX11Extras")

    assert QtX11Extras is not None
    # This module doesn't seem to contain any classes
    # See https://doc.qt.io/qt-5/qtx11extras-module.html
