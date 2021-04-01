import QtQuick 2.6

Item {
    id: rootItem
    width: visbut.width + 10
    height: visbut.height + 10

    signal clicked
    property string text

    Rectangle {
        id: visbut
        border {
            color: '#444444'
            width: 2
        }
        color: '#dddddd'
        radius: 4

        anchors.centerIn: parent
        width: buttonText.width
        height: buttonText.height

        MouseArea {
            anchors.fill: parent
            onClicked: rootItem.clicked()
        }
    }

    Text {
        id: buttonText
        leftPadding: 30
        rightPadding: 30
        topPadding: 20
        bottomPadding: 20
        verticalAlignment: Text.AlignVCenter
        text: rootItem.text
        color: 'red'
    }

}
