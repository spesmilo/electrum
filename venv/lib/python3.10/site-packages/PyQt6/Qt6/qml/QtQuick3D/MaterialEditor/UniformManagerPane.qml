// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import QtQuick3D.MaterialEditor

Pane {
    id: uniformManagerPane
    property alias uniformModel: uniformModel
    required property MaterialAdapter materialAdapter
    SplitView {
        anchors.fill: parent
        ColumnLayout {
            clip: true
            RowLayout {
                id: tableControls

                function insertUniform() {
                    let rowCount = uniformManagerPane.materialAdapter.uniformModel.rowCount;
                    if (uniformManagerPane.materialAdapter.uniformModel.insertRow(rowCount, typeComboBox.currentIndex, uniformNameTextInput.text))
                        uniformNameTextInput.text = ""
                }

                Label {
                    text: "Type:"
                }

                ComboBox {
                    id: typeComboBox
                    textRole: "text"
                    valueRole: "value"
                    model: [
                        { value: UniformModel.Bool, text: "bool" },
                        { value: UniformModel.Int, text: "int" },
                        { value: UniformModel.Float, text: "float" },
                        { value: UniformModel.Vec2, text: "vec2" },
                        { value: UniformModel.Vec3, text: "vec3" },
                        { value: UniformModel.Vec4, text: "vec4" },
                        { value: UniformModel.Mat44, text: "mat44" },
                        { value: UniformModel.Sampler, text: "sampler" }
                    ]
                }

                TextField {
                    id: uniformNameTextInput
                    validator: RegularExpressionValidator {
                        regularExpression: /[a-zA-Z_][a-zA-Z0-9_]+/
                    }
                    Layout.fillWidth: true
                    placeholderText: "Uniform Name"
                    onAccepted: tableControls.insertUniform()
                }
                Button {
                    id: addButton
                    text: "Add"
                    enabled: uniformNameTextInput.text != ""
                    onClicked: tableControls.insertUniform()
                }
            }

            //          Column Header
            Row {
                id: columnsHeader
                Layout.fillWidth: true
                Label {
                    width: uniformTable.columnWidth(0)
                    text: "Type"
                    verticalAlignment: Text.AlignVCenter
                }
                Label {
                    width: uniformTable.columnWidth(1)
                    text: "Name"
                    verticalAlignment: Text.AlignVCenter
                }
                Label {
                    width: uniformTable.columnWidth(2)
                    text: "Value"
                    verticalAlignment: Text.AlignVCenter
                }
            }
            ListView {
                id: uniformTable
                Layout.fillHeight: true
                Layout.fillWidth: true
                flickableDirection: Flickable.VerticalFlick
                model: UniformModel {
                    id: uniformModel
                }
                clip: true
                ScrollBar.vertical: ScrollBar { }
                highlight: Rectangle {
                    color: palette.highlight
                }

                property var typeStrings: [
                    "bool",
                    "int",
                    "float",
                    "vec2",
                    "vec3",
                    "vec4",
                    "mat44",
                    "sampler"
                ]

                function convertValueToString(value, type)
                {
                    if (type === 0) {
                        // bool
                        return String(value);
                    } if (type === 1) {
                        // int
                        return String(value);
                    } if (type === 2) {
                        // float
                        return String(value);
                    } if (type === 3) {
                        // vec2
                        return "(" + value.x + ", " + value.y + ")"
                    } if (type === 4) {
                        // vec3
                        return "(" + value.x + ", " + value.y + ", " + value.z + ")"
                    } if (type === 5) {
                        // vec4
                        return "(" + value.x + ", " + value.y + ", " + value.z + ", " + value.w + ")"
                    } if (type === 6) {
                        // mat44
                        return value.toString()
                    } if (type === 7) {
                        // sampler
                        return "[Texture]"
                    }
                }

                function columnWidth(column) {
                    if (column === 0)
                        return 50;
                    if (column === 1)
                        return 100;
                    return 100;
                }

                delegate: Item {
                    id: delegateRoot
                    required property int type
                    required property string name
                    required property var value
                    required property int index


                    width: ListView.view.width
                    height: typeLabel.implicitHeight
                    Row {
                        Label {
                            id: typeLabel
                            width: uniformTable.columnWidth(0)
                            text: uniformTable.typeStrings[delegateRoot.type]
                        }
                        Label {
                            width: uniformTable.columnWidth(1)
                            text: delegateRoot.name
                        }
                        Label {
                            width: uniformTable.columnWidth(2)
                            Layout.fillWidth: true
                            text: uniformTable.convertValueToString(delegateRoot.value, delegateRoot.type)
                        }
                    }
                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            uniformTable.currentIndex = delegateRoot.index
                        }
                    }
                }
            }
        }


        Item {
            id: uniformValueEditor
            width: parent.width * 0.5
            clip: true

            Label {
                id: emptyLabel
                visible: uniformTable.currentIndex == -1
                anchors.centerIn: parent
                text: "Select a uniform to edit"
            }

            Repeater {
                id: delegateRepeater
                anchors.fill: parent
                model: uniformModel
                Item {
                    id: editorRoot

                    required property int index
                    required property int type
                    required property string name
                    required property var model

                    anchors.fill: parent
                    anchors.margins: 10
                    visible: index === uniformTable.currentIndex

                    Item {
                        id: header
                        width: parent.width
                        anchors.top: parent.top
                        height: removeButton.implicitHeight
                        RowLayout {
                            anchors.fill: parent
                            id: headerLayout
                            Label {
                                text: "Uniform: " + editorRoot.name
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                            Button {
                                id: removeButton
                                text: "Remove"
                                Layout.alignment: Qt.AlignRight
                                onClicked: {
                                    uniformManagerPane.materialAdapter.uniformModel.removeRow(uniformTable.currentIndex, 1)
                                }
                            }
                        }
                    }

                    Loader {
                        id: editorLoader
                        anchors.top: header.bottom
                        anchors.right: parent.right
                        anchors.left: parent.left
                        anchors.bottom: parent.bottom
                        sourceComponent: editors[editorRoot.type]


                        readonly property list<Component> editors: [
                            boolEditor,
                            intEditor,
                            floatEditor,
                            vec2Editor,
                            vec3Editor,
                            vec4Editor,
                            mat44Editor,
                            samplerEditor
                        ]

                        Component {
                            id: boolEditor
                            CheckBox {
                                text: "value"
                                checked: editorRoot.model.value
                                onCheckedChanged: editorRoot.model.value = checked
                            }
                        }

                        Component {
                            id: intEditor
                            TextField {
                                text: editorRoot.model.value
                                validator: IntValidator {
                                    locale: "C"
                                }
                                onEditingFinished:{
                                    if (acceptableInput)
                                        editorRoot.model.value = parseInt(text)
                                }
                            }
                        }

                        Component {
                            id: floatEditor
                            ColumnLayout {
                                TextField {
                                    Layout.fillWidth: true
                                    text: editorRoot.model.value
                                    validator: DoubleValidator {
                                        locale: "C"
                                    }
                                    onEditingFinished:{
                                        if (acceptableInput) {
                                            var floatValue = parseFloat(text);
                                            floatSlider.updateMinMax(floatValue);
                                            editorRoot.value = floatValue;
                                        }
                                    }
                                }
                                Slider {
                                    id: floatSlider
                                    // Grow slider min & max based on given values
                                    function updateMinMax(newValue) {
                                        if (from > newValue)
                                            from = newValue;
                                        if (to < newValue)
                                            to = newValue;
                                        value = newValue;
                                    }
                                    from: 0.0
                                    to: 1.0
                                    onValueChanged: {
                                        editorRoot.model.value = value;
                                    }
                                    Component.onCompleted: {
                                        updateMinMax(editorRoot.model.value);
                                    }
                                }
                            }
                        }

                        Component {
                            id: vec2Editor
                            ColumnLayout {
                                RowLayout {
                                    Label {
                                        text: "X:"
                                    }
                                    TextField {
                                        id: xField
                                        text: editorRoot.model.value.x
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished: {
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector2d(parseFloat(text), editorRoot.model.value.y)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "Y:"
                                    }
                                    TextField {
                                        id: yField
                                        text: editorRoot.model.value.y
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished: {
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector2d(editorRoot.model.value.x, parseFloat(text))
                                        }
                                    }
                                }
                            }
                        }

                        Component {
                            id: vec3Editor
                            ColumnLayout {
                                RowLayout {
                                    Label {
                                        text: "X:"
                                    }
                                    TextField {
                                        id: xField
                                        text: editorRoot.model.value.x
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector3d(parseFloat(text), editorRoot.model.value.y, editorRoot.model.value.z)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "Y:"
                                    }
                                    TextField {
                                        id: yField
                                        text: editorRoot.model.value.y
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector3d(editorRoot.model.value.x, parseFloat(text), editorRoot.model.value.z)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "Z:"
                                    }
                                    TextField {
                                        id: zField
                                        text: editorRoot.model.value.z
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector3d(editorRoot.model.value.x, editorRoot.model.value.y, parseFloat(text))
                                        }
                                    }
                                }
                            }
                        }

                        Component {
                            id: vec4Editor
                            ColumnLayout {
                                RowLayout {
                                    Label {
                                        text: "X:"
                                    }
                                    TextField {
                                        id: xField
                                        text: editorRoot.model.value.x
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector4d(parseFloat(text), editorRoot.model.value.y, editorRoot.model.value.z, editorRoot.model.value.w)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "Y:"
                                    }
                                    TextField {
                                        id: yField
                                        text: editorRoot.model.value.y
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector4d(editorRoot.model.value.x, parseFloat(text), editorRoot.model.value.z, editorRoot.model.value.w)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "Z:"
                                    }
                                    TextField {
                                        id: zField
                                        text: editorRoot.model.value.z
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector4d(editorRoot.model.value.x, editorRoot.model.value.y, parseFloat(text), editorRoot.model.value.w)
                                        }
                                    }
                                }
                                RowLayout {
                                    Label {
                                        text: "W:"
                                    }
                                    TextField {
                                        id: wField
                                        text: editorRoot.model.value.w
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.vector4d(editorRoot.model.value.x, editorRoot.model.value.y, editorRoot.model.value.z, parseFloat(text))
                                        }
                                    }
                                }
                            }
                        }

                        Component {
                            id: mat44Editor
                            ColumnLayout {
                                RowLayout {
                                    TextField {
                                        text: editorRoot.model.value.m11
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(parseFloat(text), editorRoot.model.value.m12, editorRoot.model.value.m13 , editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m12
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, parseFloat(text), editorRoot.model.value.m13 , editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m13
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, parseFloat(text), editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m14
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, parseFloat(text),
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                }
                                RowLayout {
                                    TextField {
                                        text: editorRoot.model.value.m21
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            parseFloat(text), editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m22
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, parseFloat(text), editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m23
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, parseFloat(text), editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m24
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, parseFloat(text),
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                }
                                RowLayout {
                                    TextField {
                                        text: editorRoot.model.value.m31
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            parseFloat(text), editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m32
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, parseFloat(text), editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m33
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, parseFloat(text), editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m34
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, parseFloat(text),
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                }
                                RowLayout {
                                    TextField {
                                        text: editorRoot.model.value.m41
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            parseFloat(text), editorRoot.model.value.m42, editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m42
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, parseFloat(text), editorRoot.model.value.m43, editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m43
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, parseFloat(text), editorRoot.model.value.m44)
                                        }
                                    }
                                    TextField {
                                        text: editorRoot.model.value.m44
                                        validator: DoubleValidator {
                                            locale: "C"
                                        }
                                        onEditingFinished:{
                                            if (acceptableInput)
                                                editorRoot.model.value = Qt.matrix4x4(editorRoot.model.value.m11, editorRoot.model.value.m12, editorRoot.model.value.m13, editorRoot.model.value.m14,
                                                                                            editorRoot.model.value.m21, editorRoot.model.value.m22, editorRoot.model.value.m23, editorRoot.model.value.m24,
                                                                                            editorRoot.model.value.m31, editorRoot.model.value.m32, editorRoot.model.value.m33, editorRoot.model.value.m34,
                                                                                            editorRoot.model.value.m41, editorRoot.model.value.m42, editorRoot.model.value.m43, parseFloat(text))
                                        }
                                    }
                                }
                            }
                        }

                        Component {
                            id: samplerEditor
                            ColumnLayout {
                                Image {
                                    id: previewImage
                                    sourceSize.width: 128
                                    sourceSize.height: 128
                                    fillMode: Image.PreserveAspectFit
                                }
                                Button {
                                    text: "Choose Image"
                                    onClicked: {
                                        textureSourceDialog.open()
                                    }
                                }
                                FileDialog {
                                    id: textureSourceDialog
                                    title: "Open an Image File"
                                    nameFilters: [ uniformManagerPane.materialAdapter.getSupportedImageFormatsFilter()]
                                    onAccepted: {
                                        if (textureSourceDialog.selectedFile !== null) {
                                            editorRoot.model.value = textureSourceDialog.selectedFile
                                            previewImage.source = textureSourceDialog.selectedFile
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
