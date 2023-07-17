import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog
    title: qsTr("Detect BIP39 accounts")

    property string seed
    property string seedExtraWords
    property string walletType

    property string derivationPath
    property string scriptType

    z: 1 // raise z so it also covers wizard dialog

    anchors.centerIn: parent

    padding: 0

    width: parent.width * 4/5
    height: parent.height * 4/5

    ColumnLayout {
        id: rootLayout
        width: parent.width
        height: parent.height

        InfoTextArea {
            Layout.fillWidth: true
            Layout.margins: constants.paddingMedium

            text: bip39RecoveryListModel.state == Bip39RecoveryListModel.Scanning
                ? qsTr('Scanning for accounts...')
                : bip39RecoveryListModel.state == Bip39RecoveryListModel.Success
                    ? listview.count > 0
                        ? qsTr('Choose an account to restore.')
                        : qsTr('No existing accounts found.')
                    : bip39RecoveryListModel.state == Bip39RecoveryListModel.Failed
                        ? qsTr('Recovery failed')
                        : qsTr('Recovery cancelled')
            iconStyle: bip39RecoveryListModel.state == Bip39RecoveryListModel.Scanning
                ? InfoTextArea.IconStyle.Spinner
                : bip39RecoveryListModel.state == Bip39RecoveryListModel.Success
                    ? InfoTextArea.IconStyle.Info
                    : InfoTextArea.IconStyle.Error
        }

        Frame {
            id: accountsFrame
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium

            verticalPadding: 0
            horizontalPadding: 0
            background: PaneInsetBackground {}

            ColumnLayout {
                spacing: 0
                anchors.fill: parent

                ListView {
                    id: listview
                    Layout.preferredWidth: parent.width
                    Layout.fillHeight: true
                    clip: true
                    model: bip39RecoveryListModel

                    delegate: ItemDelegate {
                        width: ListView.view.width
                        height: itemLayout.height

                        onClicked: {
                            dialog.derivationPath = model.derivation_path
                            dialog.scriptType = model.script_type
                            dialog.doAccept()
                        }

                        GridLayout {
                            id: itemLayout
                            columns: 3
                            rowSpacing: 0

                            anchors {
                                left: parent.left
                                right: parent.right
                                leftMargin: constants.paddingMedium
                                rightMargin: constants.paddingMedium
                            }

                            Item {
                                Layout.columnSpan: 3
                                Layout.preferredHeight: constants.paddingLarge
                                Layout.preferredWidth: 1
                            }
                            Image {
                                Layout.rowSpan: 3
                                source: Qt.resolvedUrl('../../icons/wallet.png')
                            }
                            Label {
                                Layout.columnSpan: 2
                                Layout.fillWidth: true
                                text: model.description
                                wrapMode: Text.Wrap
                            }
                            Label {
                                text: qsTr('script type')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.script_type
                            }
                            Label {
                                text: qsTr('derivation path')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.derivation_path
                            }
                            Item {
                                Layout.columnSpan: 3
                                Layout.preferredHeight: constants.paddingLarge
                                Layout.preferredWidth: 1
                            }
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }
        }
    }

    Bip39RecoveryListModel {
        id: bip39RecoveryListModel
    }

    Component.onCompleted: {
        bip39RecoveryListModel.startScan(walletType, seed, seedExtraWords)
    }
}
