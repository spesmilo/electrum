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
                master_idx: i
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
            required property int master_idx
            Layout.fillWidth: false
            Layout.preferredWidth: 2
            Layout.preferredHeight: pheight
            Layout.alignment: Qt.AlignVCenter
            color: constants.darkerBackground
            Component.onCompleted: {
                // create binding here, we need to be able to have stable ref master_idx
                visible = Qt.binding(function() {
                    let anybefore_visible = false
                    for (let j = master_idx-1; j >= 0; j--) {
                        anybefore_visible = anybefore_visible || root.itemAt(j).visible
                    }
                    return root.itemAt(master_idx).visible && anybefore_visible
                })
            }
        }
    }

}
