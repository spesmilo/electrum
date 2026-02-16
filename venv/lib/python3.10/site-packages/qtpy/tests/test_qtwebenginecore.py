import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtwebenginecore():
    """Test the qtpy.QtWebEngineCore namespace"""
    QtWebEngineCore = pytest_importorskip("qtpy.QtWebEngineCore")

    assert QtWebEngineCore.QWebEngineHttpRequest is not None
