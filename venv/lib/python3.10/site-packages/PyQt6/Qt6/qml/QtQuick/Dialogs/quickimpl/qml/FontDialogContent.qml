// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls
import QtQuick.Controls.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

GridLayout {
    property alias familyListView: fontFamilyListView
    property alias styleListView: fontStyleListView
    property alias sizeListView: fontSizeListView
    property alias sampleEdit: fontSample
    property alias underline: fontUnderline
    property alias strikeout: fontStrikeout
    property alias familyEdit: fontFamilyEdit
    property alias styleEdit: fontStyleEdit
    property alias sizeEdit: fontSizeEdit

    columns: 3

    ColumnLayout {
        spacing: 0

        Layout.preferredWidth: 50

        Label {
            text: qsTr("Family")
            Layout.alignment: Qt.AlignLeft
        }
        TextField {
            id: fontFamilyEdit
            objectName: "familyEdit"
            readOnly: true
            Layout.fillWidth: true
            focus: true
            Accessible.name: qsTr("Font family")
        }
        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            background: Rectangle {
                color: palette.base
            }
            ListView {
                id: fontFamilyListView
                objectName: "familyListView"
                implicitHeight: 200
                anchors.fill: parent
                clip: true

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AlwaysOn
                }

                boundsBehavior: Flickable.StopAtBounds

                highlightMoveVelocity: -1
                highlightMoveDuration: 1
                highlightFollowsCurrentItem: true
                keyNavigationEnabled: true

                delegate: ItemDelegate {
                    width: ListView.view.width
                    highlighted: ListView.isCurrentItem
                    onClicked: () => fontFamilyListView.currentIndex = index
                    text: modelData
                }
            }
        }
    }

    ColumnLayout {
        spacing: 0

        Layout.preferredWidth: 30

        Label {
            text: qsTr("Style")
            Layout.alignment: Qt.AlignLeft
        }
        TextField {
            id: fontStyleEdit
            objectName: "styleEdit"
            readOnly: true
            Layout.fillWidth: true
            Accessible.name: qsTr("Font style")
        }
        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            background: Rectangle {
                color: palette.base
            }
            ListView {
                id: fontStyleListView
                objectName: "styleListView"
                implicitHeight: 200
                anchors.fill: parent
                clip: true

                ScrollBar.vertical: ScrollBar {}
                boundsBehavior: Flickable.StopAtBounds

                highlightMoveVelocity: -1
                highlightMoveDuration: 1
                highlightFollowsCurrentItem: true
                keyNavigationEnabled: true

                delegate: ItemDelegate {
                    width: ListView.view.width
                    highlighted: ListView.isCurrentItem
                    onClicked: () => fontStyleListView.currentIndex = index
                    text: modelData
                }
            }
        }
    }

    ColumnLayout {
        spacing: 0

        Layout.preferredWidth: 20

        Label {
            text: qsTr("Size")
            Layout.alignment: Qt.AlignLeft
        }
        TextField {
            id: fontSizeEdit
            objectName: "sizeEdit"
            Layout.fillWidth: true
            validator: IntValidator {
                bottom: 1
                top: 512
            }
            Accessible.name: qsTr("Font point size")
        }
        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            background: Rectangle {
                color: palette.base
            }
            ListView {
                id: fontSizeListView
                objectName: "sizeListView"
                implicitHeight: 200
                anchors.fill: parent
                clip: true

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AlwaysOn
                }

                boundsBehavior: Flickable.StopAtBounds

                highlightMoveVelocity: -1
                highlightMoveDuration: 1
                highlightFollowsCurrentItem: true
                keyNavigationEnabled: true

                delegate: ItemDelegate {
                    width: ListView.view.width
                    highlighted: ListView.isCurrentItem
                    onClicked: () => fontSizeListView.currentIndex = index
                    text: modelData
                }
            }
        }
    }

    ColumnLayout {
        Layout.preferredWidth: 80

        GroupBox {
            id: effectsGroupBox
            title: qsTr("Effects")

            Layout.fillWidth: true
            Layout.fillHeight: true

            label: Label {
                anchors.left: effectsGroupBox.left
                text: parent.title
            }

            RowLayout {
                anchors.fill: parent
                CheckBox {
                    id: fontUnderline
                    objectName: "underlineEffect"
                    text: qsTr("Underline")
                }
                CheckBox{
                    id: fontStrikeout
                    objectName: "strikeoutEffect"
                    text: qsTr("Strikeout")
                }
            }
        }
    }

    GroupBox {
        id: sample
        padding: label.implicitHeight
        title: qsTr("Sample")

        Layout.fillWidth: true
        Layout.preferredWidth: 80
        Layout.fillHeight: true
        Layout.columnSpan: 2
        clip: true

        background: Rectangle {
            y: sample.topPadding - sample.bottomPadding
            width: sample.width - sample.leftPadding + sample.rightPadding
            height: sample.height - sample.topPadding + sample.bottomPadding
            radius: 3
            color: palette.base
        }

        label: Label {
            anchors.left: sample.left
            text: sample.title
        }

        TextEdit {
            id: fontSample
            objectName: "sampleEdit"
            anchors.centerIn: parent
            readOnly: true
            color: palette.text
            focusPolicy: Qt.NoFocus
            Accessible.ignored: true
        }
    }
}
