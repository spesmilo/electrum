import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtsvgwidgets():
    """Test the qtpy.QtSvgWidgets namespace"""
    QtSvgWidgets = pytest_importorskip("qtpy.QtSvgWidgets")

    assert QtSvgWidgets.QGraphicsSvgItem is not None
    assert QtSvgWidgets.QSvgWidget is not None
