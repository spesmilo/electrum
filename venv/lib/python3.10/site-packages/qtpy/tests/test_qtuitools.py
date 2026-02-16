import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtuitools():
    """Test the qtpy.QtUiTools namespace"""
    QtUiTools = pytest_importorskip("qtpy.QtUiTools")

    assert QtUiTools.QUiLoader is not None
