import pytest

from qtpy.tests.utils import pytest_importorskip


def test_qtstatemachine():
    """Test the qtpy.QtStateMachine namespace"""
    QtStateMachine = pytest_importorskip("qtpy.QtStateMachine")

    assert QtStateMachine.QAbstractState is not None
    assert QtStateMachine.QAbstractTransition is not None
    assert QtStateMachine.QEventTransition is not None
    assert QtStateMachine.QFinalState is not None
    assert QtStateMachine.QHistoryState is not None
    assert QtStateMachine.QKeyEventTransition is not None
    assert QtStateMachine.QMouseEventTransition is not None
    assert QtStateMachine.QSignalTransition is not None
    assert QtStateMachine.QState is not None
