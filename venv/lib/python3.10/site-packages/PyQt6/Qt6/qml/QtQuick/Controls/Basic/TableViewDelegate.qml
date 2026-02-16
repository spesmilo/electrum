// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import Qt.labs.qmlmodels as QtLabsQmlModels
import QtQuick.Templates as T

T.TableViewDelegate {
    id: control

    // same as AbstractButton.qml
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    highlighted: control.selected

    required property int column
    required property int row
    required property var model

    background: Rectangle {
        border.width: control.current ? 2 : Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 1 : 0
        border.color: control.current ? control.palette.highlight : control.palette.windowText
        color: control.highlighted
               ? control.palette.highlight
               : (control.tableView.alternatingRows && control.row % 2 !== 0
               ? control.palette.alternateBase : control.palette.base)
    }

    contentItem: Label {
        clip: false
        text: control.model.display ?? ""
        elide: Text.ElideRight
        color: control.highlighted ? control.palette.highlightedText : control.palette.buttonText
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

        TableView.onCommit: {
            let model = control.tableView.model
            if (!model)
                return
            // The setData() APIs are different in QAbstractItemModel and QQmlTableModel.
            // This is an issue and will be fixed later, probably by deprecating the wrong
            // API in QQmlTableModel. There is a ticket reported this issue and a workaround
            // is provided in the description: https://bugreports.qt.io/browse/QTBUG-104733
            // But temporarily we need to manage this by checking the model's type.
            let succeed = false
            const index = model.index(control.row, control.column)
            if (model instanceof QtLabsQmlModels.TableModel)
                succeed = model.setData(index, "edit", textField.text)
            else
                succeed = model.setData(index, textField.text, Qt.EditRole)
            if (!succeed)
                console.warn("The model does not allow setting the EditRole data.")
        }

        Component.onCompleted: textField.selectAll()

        TextField {
            id: textField
            anchors.fill: parent
            text: control.model.edit ?? control.model.display ?? ""
            focus: true
        }
    }
    // qmllint enable attached-property-reuse
    // qmllint enable controls-attached-property-reuse
    // qmllint enable controls-sanity
}
