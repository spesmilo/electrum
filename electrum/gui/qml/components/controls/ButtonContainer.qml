import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.0

Container {
    id: root

    property Item _layout

    function fillContentItem() {
        var contentRoot = containerLayout.createObject(root)

        contentRoot.children.length = 0 // empty array
        let total = contentChildren.length

        let rowheight = 0
        for (let i = 0; i < contentChildren.length; i++) {
            rowheight = Math.max(rowheight, root.itemAt(i).implicitHeight)
        }

        for (let i = 0; i < contentChildren.length; i++) {
            var button = root.itemAt(i)

            contentRoot.children.push(verticalSeparator.createObject(_layout, {
                pheight: rowheight * 2/3,
                visible: Qt.binding(function() {
                    let anybefore_visible = false
                    for (let j = i-1; j >= 0; j--) {
                        anybefore_visible = anybefore_visible || root.itemAt(j).visible
                    }
                    return button.visible && anybefore_visible
                })
            }))

            contentRoot.children.push(button)
        }

        contentItem = contentRoot
    }

    Component.onCompleted: fillContentItem()

    Component {
        id: containerLayout
        RowLayout {
            spacing: 0
        }
    }

    Component {
        id: verticalSeparator
        Rectangle {
            required property int pheight
            Layout.fillWidth: false
            Layout.preferredWidth: 2
            Layout.preferredHeight: pheight
            Layout.alignment: Qt.AlignVCenter
            color: constants.darkerBackground
        }
    }

}
