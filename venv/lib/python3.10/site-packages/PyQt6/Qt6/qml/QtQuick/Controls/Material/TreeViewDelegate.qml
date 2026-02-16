// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Material

T.TreeViewDelegate {
    id: control

    implicitWidth: leftMargin + __contentIndent + implicitContentWidth + rightPadding + rightMargin
    implicitHeight: Math.max(implicitBackgroundHeight, implicitContentHeight, implicitIndicatorHeight)

    indentation: indicator ? indicator.width : 12
    leftMargin: 16
    rightMargin: 16
    spacing: 14

    topPadding: contentItem ? (height - contentItem.implicitHeight) / 2 : 0
    leftPadding: !mirrored ? leftMargin + __contentIndent : width - leftMargin - __contentIndent - implicitContentWidth

    highlighted: control.selected || control.current
               || ((control.treeView.selectionBehavior === TableView.SelectRows
               || control.treeView.selectionBehavior === TableView.SelectionDisabled)
               && control.row === control.treeView.currentRow)

    required property int row
    required property var model
    readonly property real __contentIndent: !isTreeNode ? 0 : (depth * indentation) + (indicator ? indicator.width + spacing : 0)

    indicator: Item {
        readonly property real __indicatorIndent: control.leftMargin + (control.depth * control.indentation)
        x: !control.mirrored ? __indicatorIndent : control.width - __indicatorIndent - width
        y: (control.height - height) / 2
        implicitWidth: Math.max(arrow.implicitWidth, 20)
        implicitHeight: control.Material.buttonHeight

        property ColorImage arrow : ColorImage {
            parent: control.indicator
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            rotation:  control.expanded ? 90 : (control.mirrored ? 180 : 0)
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Material/images/arrow-indicator.png"
            color: control.enabled ? control.Material.foreground : control.Material.hintTextColor
            defaultColor: "#353637"
        }
    }

    background: Rectangle {
        implicitHeight: control.Material.buttonHeight
        color: control.highlighted
               ? control.Material.accentColor
               : (control.treeView.alternatingRows && control.row % 2 !== 0
                  ? control.Material.background
                  // The Material.shade() is used as the alternate background color for rows
                  // based on the Material.theme value.
                  : control.Material.shade(control.Material.background,
                                           control.Material.theme === Material.Dark
                                           ? Material.Shade100 // the lighter background color
                                           : Material.Shade700 // the darker background color
                                           ))
    }

    contentItem: Label {
        text: control.model.display
        elide: Text.ElideRight
        visible: !control.editing
    }

    // The edit delegate is a separate component, and doesn't need
    // to follow the same strict rules that are applied to a control.
    // qmllint disable attached-property-reuse
    // qmllint disable controls-attached-property-reuse
    // qmllint disable controls-sanity
    TableView.editDelegate: FocusScope {
        width: parent.width
        height: parent.height

        readonly property int __role: {
            let model = control.treeView.model
            let index = control.treeView.index(row, column)
            let editText = model.data(index, Qt.EditRole)
            return editText !== undefined ? Qt.EditRole : Qt.DisplayRole
        }

        TextField {
            id: textField
            x: control.contentItem.x
            y: (parent.height - height) / 2
            width: control.contentItem.width
            text: control.treeView.model.data(control.treeView.index(row, column), __role)
            focus: true
        }

        TableView.onCommit: {
            let index = TableView.view.index(row, column)
            TableView.view.model.setData(index, textField.text, __role)
        }

        Component.onCompleted: textField.selectAll()
    }
    // qmllint enable attached-property-reuse
    // qmllint enable controls-attached-property-reuse
    // qmllint enable controls-sanity
}
