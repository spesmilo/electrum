import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtaxcontainer():
    """Test the qtpy.QtAxContainer namespace"""
    QtAxContainer = pytest_importorskip("qtpy.QtAxContainer")

    assert QtAxContainer.QAxSelect is not None
    assert QtAxContainer.QAxWidget is not None
