import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtpdfwidgets():
    """Test the qtpy.QtPdfWidgets namespace"""
    QtPdfWidgets = pytest_importorskip("qtpy.QtPdfWidgets")

    assert QtPdfWidgets.QPdfView is not None
