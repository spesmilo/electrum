// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Dynamic Rigid Body")

        SectionLayout {
            id: baseSectionLayout

            property bool isDefaultDensityMode: massModeComboBox.currentIndex === 0
            property bool isCustomDensityMode: massModeComboBox.currentIndex === 1
            property bool isMassMode: massModeComboBox.currentIndex === 2
            property bool isMassAndInertiaTensorMode: massModeComboBox.currentIndex === 3
            property bool isMassAndInertiaMatrixMode: massModeComboBox.currentIndex === 4

            PropertyLabel {
                text: "Mass Mode"
                tooltip: "Describes how mass and inertia are calculated for this body."
            }

            SecondColumnLayout {
                ComboBox {
                    id: massModeComboBox
                    scope: "DynamicRigidBody"
                    model: ["DefaultDensity", "CustomDensity", "Mass", "MassAndInertiaTensor", "MassAndInertiaMatrix"]
                    backendValue: backendValues.massMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: baseSectionLayout.isMassAndInertiaMatrixMode || baseSectionLayout.isMassAndInertiaTensorMode
            }

            SecondColumnLayout {
                visible: baseSectionLayout.isMassAndInertiaMatrixMode || baseSectionLayout.isMassAndInertiaTensorMode

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                Label {
                    text: qsTr("Tensor and Matrix modes require QML code.")
                    Layout.fillWidth: true
                    Layout.preferredWidth: StudioTheme.Values.singleControlColumnWidth
                    Layout.minimumWidth: StudioTheme.Values.singleControlColumnWidth
                    Layout.maximumWidth: StudioTheme.Values.singleControlColumnWidth
                }
            }

            PropertyLabel {
                visible: !baseSectionLayout.isDefaultDensityMode && !baseSectionLayout.isCustomDensityMode
                text: "Mass"
                tooltip: "The mass of the body."
            }

            SecondColumnLayout {
                visible: !baseSectionLayout.isDefaultDensityMode && !baseSectionLayout.isCustomDensityMode
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    stepSize: 0.01
                    backendValue: backendValues.mass
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: baseSectionLayout.isCustomDensityMode
                text: "Density"
                tooltip: "The density of the body."
            }

            SecondColumnLayout {
                visible: baseSectionLayout.isCustomDensityMode
                SpinBox {
                    minimumValue: -1
                    maximumValue: 9999999
                    decimals: 2
                    stepSize: 0.01
                    backendValue: backendValues.density
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: "Enable Gravity"
                tooltip: "Sets if the body affected by gravity."
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.gravityEnabled.valueToString
                    backendValue: backendValues.gravityEnabled
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: "Linear Axis Lock"
                tooltip: "Lock the linear axis of the body."
            }

            SecondColumnLayout {
                ActionIndicator {
                    id: linearAxisLockController
                    icon.color: extFuncLogic.color
                    icon.text: extFuncLogic.glyph
                    onClicked: extFuncLogic.show()
                    forceVisible: extFuncLogic.menuVisible
                    visible: true

                    property var enableLockX: { "value": false, "isInModel": false}
                    property var enableLockY: { "value": false, "isInModel": false}
                    property var enableLockZ: { "value": false, "isInModel": false}

                    property variant backendValue: backendValues.linearAxisLock
                    property variant valueFromBackend: backendValue === undefined ? 0 : backendValue.value
                    property bool blockLocks: false

                    onBackendValueChanged: evaluateLocks()
                    onValueFromBackendChanged: evaluateLocks()

                    Connections {
                        target: modelNodeBackend
                        function onSelectionChanged() {
                            evaluateLevels()
                        }
                    }

                    Component.onCompleted: evaluateLocks()

                    function evaluateLocks() {
                        blockLocks = true
                        enableLockX = { "value": valueFromBackend & 1, "isInModel": false}
                        enableLockY = { "value": valueFromBackend & 2, "isInModel": false}
                        enableLockZ = { "value": valueFromBackend & 4, "isInModel": false}
                        blockLocks = false
                    }

                    function composeExpressionString() {
                        if (blockLocks)
                            return

                        let expressionStr = "";

                        if (enableLockX.value || enableLockY.value || enableLockY.value) {
                            if (enableLockX.value)
                                expressionStr += " | DynamicRigidBody.LockX";
                            if (enableLockY.value)
                                expressionStr += " | DynamicRigidBody.LockY";
                            if (enableLockZ.value)
                                expressionStr += " | DynamicRigidBody.LockZ";

                            expressionStr = expressionStr.substring(3);

                            backendValue.expression = expressionStr
                        } else {
                            expressionStr = "DynamicRigidBody.None";
                            backendValue.expression = expressionStr
                        }
                    }
                    ExtendedFunctionLogic {
                        id: extFuncLogic
                        backendValue: backendValues.linearAxisLock
                        onReseted: {
                            linearAxisLockController.enableLockX = { "value": false, "isInModel": false}
                            linearAxisLockController.enableLockY = { "value": false, "isInModel": false}
                            linearAxisLockController.enableLockZ = { "value": false, "isInModel": false}
                            linearAxisLockController.evaluateLocks()
                        }
                    }
                }
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock X")
                    backendValue: linearAxisLockController.enableLockX
                    actionIndicatorVisible: false
                    onCheckedChanged: linearAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock Y")
                    backendValue: linearAxisLockController.enableLockY
                    actionIndicatorVisible: false
                    onCheckedChanged: linearAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock Z")
                    backendValue: linearAxisLockController.enableLockZ
                    actionIndicatorVisible: false
                    onCheckedChanged: linearAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: "Angular Axis Lock"
                tooltip: "Lock the angular axis of the body."
            }

            SecondColumnLayout {
                ActionIndicator {
                    id: angularAxisLockController
                    icon.color: extFuncLogicAngular.color
                    icon.text: extFuncLogicAngular.glyph
                    onClicked: extFuncLogicAngular.show()
                    forceVisible: extFuncLogic.menuVisible
                    visible: true

                    property var enableLockX: { "value": false, "isInModel": false}
                    property var enableLockY: { "value": false, "isInModel": false}
                    property var enableLockZ: { "value": false, "isInModel": false}

                    property variant backendValue: backendValues.angularAxisLock
                    property variant valueFromBackend: backendValue === undefined ? 0 : backendValue.value
                    property bool blockLocks: false

                    onBackendValueChanged: evaluateLocks()
                    onValueFromBackendChanged: evaluateLocks()

                    Connections {
                        target: modelNodeBackend
                        function onSelectionChanged() {
                            evaluateLevels()
                        }
                    }

                    Component.onCompleted: evaluateLocks()

                    function evaluateLocks() {
                        blockLocks = true
                        enableLockX = { "value": valueFromBackend & 1, "isInModel": false}
                        enableLockY = { "value": valueFromBackend & 2, "isInModel": false}
                        enableLockZ = { "value": valueFromBackend & 4, "isInModel": false}
                        blockLocks = false
                    }

                    function composeExpressionString() {
                        if (blockLocks)
                            return

                        let expressionStr = "";

                        if (enableLockX.value || enableLockY.value || enableLockY.value) {
                            if (enableLockX.value)
                                expressionStr += " | DynamicRigidBody.LockX";
                            if (enableLockY.value)
                                expressionStr += " | DynamicRigidBody.LockY";
                            if (enableLockZ.value)
                                expressionStr += " | DynamicRigidBody.LockZ";

                            expressionStr = expressionStr.substring(3);

                            backendValue.expression = expressionStr
                        } else {
                            expressionStr = "DynamicRigidBody.None";
                            backendValue.expression = expressionStr
                        }
                    }
                    ExtendedFunctionLogic {
                        id: extFuncLogicAngular
                        backendValue: backendValues.angularAxisLock
                        onReseted: {
                            angularAxisLockController.enableLockX = { "value": false, "isInModel": false}
                            angularAxisLockController.enableLockY = { "value": false, "isInModel": false}
                            angularAxisLockController.enableLockZ = { "value": false, "isInModel": false}
                            angularAxisLockController.evaluateLocks()
                        }
                    }
                }
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock X")
                    backendValue: angularAxisLockController.enableLockX
                    actionIndicatorVisible: false
                    onCheckedChanged: angularAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock Y")
                    backendValue: angularAxisLockController.enableLockY
                    actionIndicatorVisible: false
                    onCheckedChanged: angularAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }
            PropertyLabel {
                // spacer
            }

            SecondColumnLayout {

                Item {
                    // spacer for the always hiden action indicator
                    width: StudioTheme.Values.actionIndicatorWidth
                }

                CheckBox {
                    text: qsTr("Lock Z")
                    backendValue: angularAxisLockController.enableLockZ
                    actionIndicatorVisible: false
                    onCheckedChanged: angularAxisLockController.composeExpressionString()
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: "Is Kinematic"
                tooltip: "Kinematic objects are not influenced by external forces and can be seen as an object of infinite mass."
            }

            SecondColumnLayout {
                CheckBox {
                    id: isKinematicCheckBox
                    text: backendValues.isKinematic.valueToString
                    backendValue: backendValues.isKinematic
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
                text: "Kinematic Position"
                tooltip: "The position of the kinematic object."
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPosition_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "X"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPosition_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Y"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPosition_z
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Z"
                    color: StudioTheme.Values.theme3DAxisZColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
                text: "Kinematic Rotation"
                tooltip: "The rotation of the kinematic object."
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicEulerRotation_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "X"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicEulerRotation_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Y"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicEulerRotation_z
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Z"
                    color: StudioTheme.Values.theme3DAxisZColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
                text: "Kinematic Pivot"
                tooltip: "The pivot point of the kinematic object."
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPivot_x
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "X"
                    color: StudioTheme.Values.theme3DAxisXColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPivot_y
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Y"
                    color: StudioTheme.Values.theme3DAxisYColor
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                visible: isKinematicCheckBox.checked
            }

            SecondColumnLayout {
                visible: isKinematicCheckBox.checked
                SpinBox {
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                    minimumValue: -9999999
                    maximumValue: 9999999
                    decimals: 2
                    backendValue: backendValues.kinematicPivot_z
                }

                Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                ControlLabel {
                    text: "Z"
                    color: StudioTheme.Values.theme3DAxisZColor
                }

                ExpandingSpacer {}
            }
        }
    }
}

    // Other Properties Not covered by the UI
    // QVector3D inertiaTensor
    // QVector3D centerOfMassPosition
    // QQuaternion centerOfMassRotation
    // List<float> inertiaMatrix (9 floats for a Mat3x3)

