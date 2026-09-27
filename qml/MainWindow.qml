import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import "theme"

Item {
    id: root

    property bool isEnabled: false
    property int activeRules: 0
    property int totalRules: 0
    property string blockingLevel: "aggressive"
    property bool systemHostsActive: false
    property int countAds: 0
    property int countTelemetry: 0
    property int countMalware: 0
    property int countPopups: 0
    property int countSocial: 0
    property var whitelist: []
    property var blacklist: []
    property bool dohPrevention: false
    property bool aiProtection: true
    property bool kernelActive: false
    property int pauseRemainingSecs: 0
    property string testResultMsg: ""
    property bool isTesting: false

    readonly property string enginePath: {
        var base = Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "");
        var parent = base.replace(/\/qml\/?$/, "");
        return parent + "/omablock-engine";
    }

    readonly property string statusPath: {
        var base = Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "");
        var parent = base.replace(/\/qml\/?$/, "");
        return parent + "/omablock-status";
    }

    function refresh() {
        if (!statusProc.running) {
            statusProc.running = true;
        }
    }

    function setLevel(lvl) {
        actionProc.command = [root.enginePath, "--set-level", lvl];
        actionProc.running = true;
    }

    function pauseShield(mins) {
        actionProc.command = [root.enginePath, "--pause", String(mins)];
        actionProc.running = true;
    }

    function resumeShield() {
        actionProc.command = [root.enginePath, "--resume"];
        actionProc.running = true;
    }

    function testShield() {
        root.isTesting = true;
        root.testResultMsg = "Testing DNS sinks...";
        testProc.running = true;
    }

    function toggleDohGuard() {
        actionProc.command = [root.enginePath, "--toggle-doh-guard"];
        actionProc.running = true;
    }

    function addWhitelist(domain) {
        if (!domain || domain.trim().length === 0) return;
        actionProc.command = [root.enginePath, "--whitelist-add", domain.trim()];
        actionProc.running = true;
    }

    function removeWhitelist(domain) {
        if (!domain) return;
        actionProc.command = [root.enginePath, "--whitelist-remove", domain.trim()];
        actionProc.running = true;
    }

    Process {
        id: statusProc
        command: [root.statusPath]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    var d = JSON.parse(text || "{}");
                    root.isEnabled = !!d.enabled;
                    root.blockingLevel = d.blocking_level || "aggressive";
                    root.activeRules = Number(d.active_rules) || 0;
                    root.totalRules = Number(d.total_rules) || 0;
                    root.systemHostsActive = !!d.system_hosts_active;
                    root.pauseRemainingSecs = Number(d.pause_remaining_secs) || 0;
                    root.dohPrevention = !!d.doh_prevention;
                    root.aiProtection = !!d.ai_protection;
                    root.kernelActive = !!(d.kernel_status && d.kernel_status.is_active);
                    root.whitelist = d.whitelist || [];
                    root.blacklist = d.blacklist || [];

                    if (d.category_counts) {
                        root.countAds = Number(d.category_counts.ads) || 0;
                        root.countTelemetry = Number(d.category_counts.telemetry) || 0;
                        root.countMalware = Number(d.category_counts.malware) || 0;
                        root.countPopups = Number(d.category_counts.popups) || 0;
                        root.countSocial = Number(d.category_counts.social) || 0;
                    }
                } catch(e) {
                    console.warn("Failed to parse omablock status:", e);
                }
            }
        }
    }

    Process {
        id: actionProc
        onExited: root.refresh()
    }

    Process {
        id: testProc
        command: [root.enginePath, "--test"]
        onExited: {
            root.isTesting = false;
            root.refresh();
        }
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                root.testResultMsg = (text || "").trim().slice(0, 100);
            }
        }
    }

    Component.onCompleted: refresh()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 14

        // Header Card
        Rectangle {
            Layout.fillWidth: true
            height: 68
            radius: Theme.radiusMd
            color: Theme.bgSurface
            border.color: Theme.border
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                spacing: 12

                Text {
                    text: root.isEnabled ? Theme.iconShieldCheck : Theme.iconShield
                    font.family: Theme.iconFont
                    font.pixelSize: 24
                    color: root.isEnabled ? Theme.accentSuccess : Theme.accentWarning
                }

                ColumnLayout {
                    spacing: 2
                    Text {
                        text: "OMABLOCK PRIVACY SHIELD"
                        font.family: Theme.fontFamily
                        font.pixelSize: 15
                        font.bold: true
                        color: Theme.textMain
                    }
                    Text {
                        text: "Zero-Trust Host & DNS Firewall • " + root.activeRules.toLocaleString() + " Active Rules"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        color: Theme.textMuted
                    }
                }

                Item { Layout.fillWidth: true }

                // State Badge
                Rectangle {
                    height: 32
                    implicitWidth: stateBadgeRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    RowLayout {
                        id: stateBadgeRow
                        anchors.centerIn: parent
                        spacing: 8

                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: root.isEnabled ? Theme.accentSuccess : Theme.accentWarning
                        }

                        Text {
                            text: root.isEnabled ? "PROTECTION ACTIVE" : (root.pauseRemainingSecs > 0 ? ("PAUSED (" + Math.ceil(root.pauseRemainingSecs / 60) + "m)") : "DISABLED")
                            font.family: Theme.monoFont
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                    }
                }

                // Pause / Resume Toggle
                Rectangle {
                    height: 34
                    implicitWidth: pauseBtnRow.implicitWidth + 24
                    radius: Theme.radiusSm
                    color: pauseMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    RowLayout {
                        id: pauseBtnRow
                        anchors.centerIn: parent
                        spacing: 6

                        Text {
                            text: root.isEnabled ? Theme.iconPause : Theme.iconPlay
                            font.family: Theme.iconFont
                            font.pixelSize: 12
                            color: Theme.textMain
                        }
                        Text {
                            text: root.isEnabled ? "Pause 15m" : "Resume"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                    }

                    MouseArea {
                        id: pauseMouseArea
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            if (root.isEnabled) {
                                root.pauseShield(15);
                            } else {
                                root.resumeShield();
                            }
                        }
                    }
                }

                // Refresh Button
                Rectangle {
                    width: 36
                    height: 36
                    radius: Theme.radiusSm
                    color: refreshArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    Text {
                        anchors.centerIn: parent
                        text: Theme.iconRefresh
                        font.family: Theme.iconFont
                        font.pixelSize: 14
                        color: Theme.textMain
                    }

                    MouseArea {
                        id: refreshArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.refresh()
                    }
                }
            }
        }

        // Main Body: Sevel selector, Advanced Guards and Categories
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            // Left Column: Controls & Category Gauges
            ColumnLayout {
                Layout.preferredWidth: 440
                Layout.fillHeight: true
                spacing: 12

                // Blocking Level Card
                Rectangle {
                    Layout.fillWidth: true
                    height: 110
                    radius: Theme.radiusMd
                    color: Theme.bgSurface
                    border.color: Theme.border
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text {
                            text: "BLOCKING PROFILE"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.textMuted
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Repeater {
                                model: [
                                    { id: "standard", name: "Standard", desc: "Basic Filters" },
                                    { id: "aggressive", name: "Aggressive", desc: "Telemetry & Ads" },
                                    { id: "ultimate", name: "Maximum", desc: "Anti-Popup & Track" }
                                ]

                                delegate: Rectangle {
                                    Layout.fillWidth: true
                                    height: 52
                                    radius: Theme.radiusSm
                                    color: root.blockingLevel === modelData.id ? Theme.bgCardHover : Theme.bgCard
                                    border.color: root.blockingLevel === modelData.id ? Theme.accent : Theme.border
                                    border.width: 1

                                    ColumnLayout {
                                        anchors.centerIn: parent
                                        spacing: 2
                                        Text {
                                            Layout.alignment: Qt.AlignHCenter
                                            text: modelData.name
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 11
                                            font.bold: root.blockingLevel === modelData.id
                                            color: Theme.textMain
                                        }
                                        Text {
                                            Layout.alignment: Qt.AlignHCenter
                                            text: modelData.desc
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 9
                                            color: Theme.textMuted
                                        }
                                    }

                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: root.setLevel(modelData.id)
                                    }
                                }
                            }
                        }
                    }
                }

                // Security & Privacy Guards Card
                Rectangle {
                    Layout.fillWidth: true
                    height: 130
                    radius: Theme.radiusMd
                    color: Theme.bgSurface
                    border.color: Theme.border
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text {
                            text: "ZERO-TRUST SYSTEM GUARDS"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.textMuted
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            // DoH Prevention
                            Rectangle {
                                Layout.fillWidth: true
                                height: 60
                                radius: Theme.radiusSm
                                color: Theme.bgCard
                                border.color: root.dohPrevention ? Theme.accentSuccess : Theme.border
                                border.width: 1

                                ColumnLayout {
                                    anchors.centerIn: parent
                                    spacing: 4
                                    RowLayout {
                                        spacing: 6
                                        Text { text: Theme.iconLock; font.family: Theme.iconFont; font.pixelSize: 12; color: root.dohPrevention ? Theme.accentSuccess : Theme.textMuted }
                                        Text { text: "DoH Guard"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.textMain }
                                    }
                                    Text { text: root.dohPrevention ? "Enforced" : "Permissive"; font.family: Theme.monoFont; font.pixelSize: 10; color: Theme.textMuted }
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleDohGuard()
                                }
                            }

                            // AI DGA Classifier
                            Rectangle {
                                Layout.fillWidth: true
                                height: 60
                                radius: Theme.radiusSm
                                color: Theme.bgCard
                                border.color: root.aiProtection ? Theme.accentSuccess : Theme.border
                                border.width: 1

                                ColumnLayout {
                                    anchors.centerIn: parent
                                    spacing: 4
                                    RowLayout {
                                        spacing: 6
                                        Text { text: Theme.iconBrain; font.family: Theme.iconFont; font.pixelSize: 12; color: Theme.accentSuccess }
                                        Text { text: "AI Heuristics"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.textMain }
                                    }
                                    Text { text: "DGA Detection"; font.family: Theme.monoFont; font.pixelSize: 10; color: Theme.textMuted }
                                }
                            }

                            // Kernel Netfilter
                            Rectangle {
                                Layout.fillWidth: true
                                height: 60
                                radius: Theme.radiusSm
                                color: Theme.bgCard
                                border.color: root.kernelActive ? Theme.accentSuccess : Theme.border
                                border.width: 1

                                ColumnLayout {
                                    anchors.centerIn: parent
                                    spacing: 4
                                    RowLayout {
                                        spacing: 6
                                        Text { text: Theme.iconServer; font.family: Theme.iconFont; font.pixelSize: 12; color: root.kernelActive ? Theme.accentSuccess : Theme.textMuted }
                                        Text { text: "Netfilter"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.textMain }
                                    }
                                    Text { text: root.kernelActive ? "Kernel Active" : "Host Fallback"; font.family: Theme.monoFont; font.pixelSize: 10; color: Theme.textMuted }
                                }
                            }
                        }
                    }
                }

                // Category Breakdown
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    radius: Theme.radiusMd
                    color: Theme.bgSurface
                    border.color: Theme.border
                    border.width: 1

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text {
                            text: "FILTER CATEGORY TELEMETRY"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.textMuted
                        }

                        Repeater {
                            model: [
                                { name: "Advertising & Trackers", count: root.countAds, icon: Theme.iconFilter },
                                { name: "Telemetry & Analytics", count: root.countTelemetry, icon: Theme.iconPulse },
                                { name: "Malware & Phishing C2", count: root.countMalware, icon: Theme.iconShield },
                                { name: "Popups & Fake Overlays", count: root.countPopups, icon: Theme.iconTimes }
                            ]

                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 38
                                radius: Theme.radiusSm
                                color: Theme.bgCard
                                border.color: Theme.border
                                border.width: 1

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 12
                                    spacing: 8

                                    Text {
                                        text: modelData.icon
                                        font.family: Theme.iconFont
                                        font.pixelSize: 12
                                        color: Theme.accent
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.name
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMain
                                    }

                                    Text {
                                        text: modelData.count.toLocaleString() + " domains"
                                        font.family: Theme.monoFont
                                        font.pixelSize: 11
                                        color: Theme.textMuted
                                    }
                                }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        // Sinkhole Test Trigger
                        Rectangle {
                            Layout.fillWidth: true
                            height: 36
                            radius: Theme.radiusSm
                            color: testBtnArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                anchors.centerIn: parent
                                spacing: 8
                                Text {
                                    text: Theme.iconCheck
                                    font.family: Theme.iconFont
                                    font.pixelSize: 12
                                    color: Theme.accent
                                }
                                Text {
                                    text: root.isTesting ? "Testing DNS Sinkhole..." : (root.testResultMsg.length > 0 ? root.testResultMsg : "Run DNS Sinkhole Diagnostic")
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    font.bold: true
                                    color: Theme.textMain
                                }
                            }

                            MouseArea {
                                id: testBtnArea
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.testShield()
                            }
                        }
                    }
                }
            }

            // Right Column: Whitelist / Blacklist Manager
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Theme.radiusMd
                color: Theme.bgSurface
                border.color: Theme.border
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 14
                    spacing: 12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        Text {
                            text: "CUSTOM DOMAIN EXCEPTIONS (WHITELIST)"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.textMuted
                        }

                        Item { Layout.fillWidth: true }

                        Text {
                            text: root.whitelist.length + " allowed"
                            font.family: Theme.monoFont
                            font.pixelSize: 11
                            color: Theme.textMuted
                        }
                    }

                    // Add Whitelist Domain Field
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        Rectangle {
                            Layout.fillWidth: true
                            height: 34
                            radius: Theme.radiusSm
                            color: Theme.bgCard
                            border.color: addInput.activeFocus ? Theme.borderLight : Theme.border
                            border.width: 1

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10
                                spacing: 8

                                TextInput {
                                    id: addInput
                                    Layout.fillWidth: true
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 12
                                    color: Theme.textMain
                                    clip: true
                                    onAccepted: {
                                        root.addWhitelist(text);
                                        text = "";
                                    }

                                    Text {
                                        anchors.fill: parent
                                        text: "Enter trusted domain (e.g. tracking.example.com)..."
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 12
                                        color: Theme.textDim
                                        visible: !addInput.text && !addInput.activeFocus
                                    }
                                }
                            }
                        }

                        Rectangle {
                            width: 34
                            height: 34
                            radius: Theme.radiusSm
                            color: addBtnArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            Text {
                                anchors.centerIn: parent
                                text: Theme.iconPlus
                                font.family: Theme.iconFont
                                font.pixelSize: 12
                                color: Theme.accentSuccess
                            }

                            MouseArea {
                                id: addBtnArea
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    root.addWhitelist(addInput.text);
                                    addInput.text = "";
                                }
                            }
                        }
                    }

                    // Whitelist List
                    ListView {
                        id: wlListView
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 6
                        model: root.whitelist

                        delegate: Rectangle {
                            width: wlListView.width
                            height: 36
                            radius: Theme.radiusSm
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 12
                                anchors.rightMargin: 8
                                spacing: 8

                                Text {
                                    text: Theme.iconCheck
                                    font.family: Theme.iconFont
                                    font.pixelSize: 11
                                    color: Theme.accentSuccess
                                }

                                Text {
                                    Layout.fillWidth: true
                                    text: modelData
                                    font.family: Theme.monoFont
                                    font.pixelSize: 11
                                    color: Theme.textMain
                                }

                                Rectangle {
                                    width: 24
                                    height: 24
                                    radius: 3
                                    color: delArea.containsMouse ? Theme.bgCardHover : "transparent"

                                    Text {
                                        anchors.centerIn: parent
                                        text: Theme.iconTrash
                                        font.family: Theme.iconFont
                                        font.pixelSize: 11
                                        color: Theme.accentDanger
                                    }

                                    MouseArea {
                                        id: delArea
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: root.removeWhitelist(modelData)
                                    }
                                }
                            }
                        }

                        Text {
                            anchors.centerIn: parent
                            visible: root.whitelist.length === 0
                            text: "No custom domain overrides defined.\nAll 470k+ community rules applied."
                            horizontalAlignment: Text.AlignHCenter
                            font.family: Theme.fontFamily
                            font.pixelSize: 12
                            color: Theme.textMuted
                        }
                    }
                }
            }
        }
    }
}
