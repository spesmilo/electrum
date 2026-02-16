import pytest

from qtpy import PYSIDE2, PYSIDE6
from qtpy.tests.utils import pytest_importorskip


@pytest.mark.skipif(
    not (PYSIDE2 or PYSIDE6),
    reason="Only available by default in PySide",
)
def test_qtcharts():
    """Test the qtpy.QtCharts namespace"""
    QtCharts = pytest_importorskip("qtpy.QtCharts")

    assert QtCharts.QChart is not None
    assert QtCharts.QtCharts.QChart is not None
