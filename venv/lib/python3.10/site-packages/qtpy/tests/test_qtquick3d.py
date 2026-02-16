import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtquick3d():
    """Test the qtpy.QtQuick3D namespace"""
    QtQuick3D = pytest_importorskip("qtpy.QtQuick3D")

    assert QtQuick3D.QQuick3D is not None
    assert QtQuick3D.QQuick3DGeometry is not None
    assert QtQuick3D.QQuick3DObject is not None
