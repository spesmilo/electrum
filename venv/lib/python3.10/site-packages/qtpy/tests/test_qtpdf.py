import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtpdf():
    """Test the qtpy.QtPdf namespace"""
    QtPdf = pytest_importorskip("qtpy.QtPdf")

    assert QtPdf.QPdfDocument is not None
    assert QtPdf.QPdfLink is not None
    assert QtPdf.QPdfSelection is not None
