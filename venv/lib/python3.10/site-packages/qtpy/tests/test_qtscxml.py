import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtscxml():
    """Test the qtpy.QtScxml namespace"""
    QtScxml = pytest_importorskip("qtpy.QtScxml")

    assert QtScxml.QScxmlCompiler is not None
    assert QtScxml.QScxmlDynamicScxmlServiceFactory is not None
    assert QtScxml.QScxmlExecutableContent is not None
