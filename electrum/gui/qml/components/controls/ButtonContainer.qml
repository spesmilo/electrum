import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Container {
    id: root

    property bool showSeparator: true
    property color separatorColor: constants.darkerBackground
    property Component headerComponent: Component {
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 2
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            color: root.separatorColor
        }
    }

    property var _contentRootItem
    property var _headerItem
    property Item _layout

    function fillContentItem() {
        var outerLayout = rootLayout.createObject(root)
        if (headerComponent != null)
            _headerItem = headerComponent.createObject(outerLayout)
        var contentRoot = containerLayout.createObject(outerLayout)

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

        contentItem = outerLayout //contentRoot
        _contentRootItem = contentRoot
    }

    // override this function to dynamically add buttons.
    function beforeLayout() {}

    Component.onCompleted: {
        beforeLayout()
        fillContentItem()
    }

    Component {
        id: rootLayout
        ColumnLayout {
            spacing: 0
        }
    }

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
            Layout.preferredWidth: showSeparator ? 2 : 0
            Layout.preferredHeight: pheight
            Layout.alignment: Qt.AlignVCenter
            color: root.separatorColor
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
