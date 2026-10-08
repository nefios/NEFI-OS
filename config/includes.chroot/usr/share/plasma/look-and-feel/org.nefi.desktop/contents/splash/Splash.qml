import QtQuick 2.15

Rectangle {
    id: root
    color: "#0e150c"
    property int stage

    Image {
        id: logo
        anchors.centerIn: parent
        anchors.verticalCenterOffset: -50
        source: "images/logo.png"
        width: 160
        height: 160
        fillMode: Image.PreserveAspectFit
        smooth: true
    }

    Text {
        id: title
        anchors.top: logo.bottom
        anchors.topMargin: 20
        anchors.horizontalCenter: parent.horizontalCenter
        text: "NEFI OS"
        color: "#e0e6de"
        font.pixelSize: 26
        font.bold: true
        font.letterSpacing: 4
    }

    Rectangle {
        anchors.top: title.bottom
        anchors.topMargin: 24
        anchors.horizontalCenter: parent.horizontalCenter
        width: 220
        height: 4
        radius: 2
        color: "#22361d"

        Rectangle {
            width: parent.width * Math.min(1, root.stage / 6)
            height: parent.height
            radius: 2
            color: "#7ac943"
            Behavior on width { NumberAnimation { duration: 400 } }
        }
    }
}
