import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtquickcontrols2():
    """Test the qtpy.QtQuickControls2 namespace"""
    QtQuickControls2 = pytest_importorskip("qtpy.QtQuickControls2")

    assert QtQuickControls2.QQuickStyle is not None
