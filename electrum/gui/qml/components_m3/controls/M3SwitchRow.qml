import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// List row with a switch on the right. `checked` (inherited, the row is not checkable, so a tap
// does not flip it) is meant to be BOUND to a backend property; userToggled(checked) is emitted
// only on user action (tap on the switch or anywhere on the row), so the initial value writes
// nothing. The handler writes the backend; the binding updates the row.
M3ListItem {
    id: root

    signal userToggled(bool checked)

    checkable: false
    onClicked: root.userToggled(!root.checked)

    trailing: Component {
        Switch {
            id: sw
            checked: root.checked
            enabled: root.enabled
            onToggled: {
                var value = sw.checked
                sw.checked = Qt.binding(function() { return root.checked })
                root.userToggled(value)
            }
        }
    }
}
