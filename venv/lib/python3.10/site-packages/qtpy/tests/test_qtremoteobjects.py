import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtremoteobjects():
    """Test the qtpy.QtRemoteObjects namespace"""
    QtRemoteObjects = pytest_importorskip("qtpy.QtRemoteObjects")

    assert QtRemoteObjects.QRemoteObjectAbstractPersistedStore is not None
    assert QtRemoteObjects.QRemoteObjectDynamicReplica is not None
    assert QtRemoteObjects.QRemoteObjectHost is not None
    assert QtRemoteObjects.QRemoteObjectHostBase is not None
    assert QtRemoteObjects.QRemoteObjectNode is not None
