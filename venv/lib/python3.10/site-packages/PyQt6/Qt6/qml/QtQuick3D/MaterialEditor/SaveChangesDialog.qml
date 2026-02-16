// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

import QtQuick
import QtQuick.Controls
import QtQuick3D.MaterialEditor

Dialog {
    id: root
    title: qsTr("Unsaved changes")
    modal: true

    required property MaterialAdapter materialAdapter
    required property var saveAsDialog

    function doIfChangesSavedOrDiscarded(actionFunction) {
        if (!materialAdapter.unsavedChanges) {
            actionFunction()
            return
        }

        // There are unsaved changes, so we need to prompt.

        function disconnectSaveChangesSignals() {
            root.accepted.disconnect(saveChanges)
            root.discarded.disconnect(discardChanges)
            root.rejected.disconnect(cancel)
        }

        function saveChanges() {
            if (materialAdapter.materialSaveFile.toString().length > 0) {
                // Existing project; can save without a dialog.
                if (materialAdapter.save()) {
                    // Saved successfully, so now we can perform the action.
                    performAction()
                } else {
                    // Failed to save; cancel.
                    cancel()
                }
            } else {
                // New project; need to save as.
                function disconnectSaveAsSignals() {
                    materialAdapter.errorOccurred.disconnect(saveAsFailed)
                    materialAdapter.postMaterialSaved.disconnect(saveAsSucceeded)
                    saveAsDialog.rejected.disconnect(saveAsDialogRejected)
                }

                function saveAsSucceeded() {
                    disconnectSaveAsSignals()
                    performAction()
                }

                function saveAsFailed() {
                    disconnectSaveAsSignals()
                    disconnectSaveChangesSignals()
                }

                function saveAsDialogRejected() {
                    disconnectSaveAsSignals()
                    cancel()
                }

                materialAdapter.errorOccurred.connect(saveAsFailed)
                materialAdapter.postMaterialSaved.connect(saveAsSucceeded)
                saveAsDialog.rejected.connect(saveAsDialogRejected)

                saveAsDialog.open()
            }
        }

        function discardChanges() {
            performAction()
            root.close()
        }

        function performAction() {
            disconnectSaveChangesSignals()
            actionFunction()
        }

        function cancel() {
            disconnectSaveChangesSignals()
        }

        root.accepted.connect(saveChanges)
        root.discarded.connect(discardChanges)
        root.rejected.connect(cancel)
        root.open()
    }

    Label {
        text: qsTr("Save changes to the material before closing?")
    }

    // Using a DialogButtonBox allows us to assign objectNames to the buttons,
    // which makes it possible to test them.
    footer: DialogButtonBox {
        Button {
            objectName: "cancelDialogButton"
            text: qsTr("Cancel")
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }
        Button {
            objectName: "saveChangesDialogButton"
            text: qsTr("Save")
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
        }
        Button {
            objectName: "discardChangesDialogButton"
            text: qsTr("Don't save")
            DialogButtonBox.buttonRole: DialogButtonBox.DestructiveRole
        }
    }
}
