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

    property bool catAds: true
    property bool catTelemetry: true
    property bool catMalware: true
    property bool catPopups: true
    property bool catSocial: false

    property int countAds: 0
    property int countTelemetry: 0
    property int countMalware: 0
    property int countPopups: 0
    property int countSocial: 0

    property var whitelist: []
    property var blacklist: []
    property string activeListTab: "whitelist"

    property bool dohPrevention: false
    property bool aiProtection: true
    property bool kernelActive: false
    property int pauseRemainingSecs: 0
    property string testResultMsg: ""
    property bool isTesting: false
    property bool isUpdating: false

    property bool networkBlackoutActive: false
    property bool usbArmorEnabled: false
    property string selfIntegrityHash: ""
    property bool idnHomographDetected: false

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

    // Status polling and the serialized action queue live in EngineClient.
    function refresh() { engine.refresh() }

    function runAction(cmd, okMsg) { engine.runAction(cmd, okMsg) }

    function reportAction(exitCode, okMsg) {
        if (exitCode === 0) {
            if (okMsg) root.testResultMsg = okMsg;
        } else if (exitCode === 2) {
            root.testResultMsg = "Rejected: invalid domain or option";
        } else {
            root.testResultMsg = "Action failed (code " + exitCode + ")";
        }
    }

    function toggleBlackout() {
        root.runAction([root.enginePath, root.networkBlackoutActive ? "--resume-network" : "--panic-blackout"]);
    }

    function toggleUsbArmor() {
        root.runAction([root.enginePath, "--toggle-usb-armor"]);
    }

    function toggleShield() {
        root.runAction([root.enginePath, "--toggle"]);
    }

    function setLevel(lvl) {
        root.runAction([root.enginePath, "--set-level", lvl]);
    }

    function pauseShield(mins) {
        root.runAction([root.enginePath, "--pause", String(mins)]);
    }

    function resumeShield() {
        root.runAction([root.enginePath, "--resume"]);
    }

    function testShield() {
        root.isTesting = true;
        root.testResultMsg = "Testing DNS sinks...";
        testProc.running = true;
    }

    function toggleDohGuard() {
        root.runAction([root.enginePath, "--toggle-doh-guard"]);
    }

    function toggleAi() {
        root.runAction([root.enginePath, "--toggle-ai"]);
    }

    function toggleKernel() {
        root.runAction([root.enginePath, "--toggle-kernel"]);
    }

    function toggleCategory(cat) {
        root.runAction([root.enginePath, "--toggle-category", cat]);
    }

    function addWhitelist(domain) {
        if (!domain || domain.trim().length === 0) return;
        root.runAction([root.enginePath, "--whitelist-add", domain.trim()]);
    }

    function removeWhitelist(domain) {
        if (!domain) return;
        root.runAction([root.enginePath, "--whitelist-remove", domain.trim()]);
    }

    function addBlacklist(domain) {
        if (!domain || domain.trim().length === 0) return;
        root.runAction([root.enginePath, "--blacklist-add", domain.trim()]);
    }

    function removeBlacklist(domain) {
        if (!domain) return;
        root.runAction([root.enginePath, "--blacklist-remove", domain.trim()]);
    }

    function flushDns() {
        root.runAction([root.enginePath, "--flush"]);
    }

    function updateBlocklists() {
        if (root.isUpdating) return;
        root.isUpdating = true;
        updateProc.running = true;
    }

    function applyStatus(d) {
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
        root.networkBlackoutActive = !!d.network_blackout_active;
        root.usbArmorEnabled = !!d.usb_armor_enabled;
        root.selfIntegrityHash = d.self_integrity_hash || "";
        root.idnHomographDetected = !!d.idn_homograph_detected;

        if (d.categories) {
            root.catAds = !!d.categories.ads;
            root.catTelemetry = !!d.categories.telemetry;
            root.catMalware = !!d.categories.malware;
            root.catPopups = !!d.categories.popups;
            root.catSocial = !!d.categories.social;
        }

        if (d.category_counts) {
            root.countAds = Number(d.category_counts.ads) || 0;
            root.countTelemetry = Number(d.category_counts.telemetry) || 0;
            root.countMalware = Number(d.category_counts.malware) || 0;
            root.countPopups = Number(d.category_counts.popups) || 0;
            root.countSocial = Number(d.category_counts.social) || 0;
        }
    }

    EngineClient {
        id: engine
        statusCommand: [root.statusPath]
        onStatusReceived: (d) => root.applyStatus(d)
        onActionFinished: (exitCode, okMsg) => root.reportAction(exitCode, okMsg)
    }

    Process {
        id: updateProc
        command: [root.enginePath, "--update"]
        onExited: {
            root.isUpdating = false;
            root.refresh();
        }
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
                try {
                    var d = JSON.parse(String(text || "").slice(0, 131072));
                    var latency = Number(d.avg_latency_ms) || 0;
                    root.testResultMsg = (d.success ? "Verified" : "Alert") + " (" + latency.toFixed(2) + "ms): " + String(d.message || "").slice(0, 100);
                } catch (e) {
                    root.testResultMsg = "Verification failed: unreadable engine output";
                }
            }
        }
    }

    Timer {
        id: pauseCountdownTimer
        interval: 1000
        repeat: true
        running: root.pauseRemainingSecs > 0
        onTriggered: {
            if (root.pauseRemainingSecs > 1) {
                root.pauseRemainingSecs -= 1;
            } else {
                root.pauseRemainingSecs = 0;
                root.refresh();
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
                        text: "Zero-Trust Host & DNS Firewall - " + root.activeRules.toLocaleString() + " Active Rules"
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

                // Master Toggle Button
                Rectangle {
                    height: 34
                    implicitWidth: masterBtnRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: masterMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                    border.color: root.isEnabled ? Theme.accentSuccess : Theme.accentWarning
                    border.width: 1

                    RowLayout {
                        id: masterBtnRow
                        anchors.centerIn: parent
                        spacing: 6

                        Text {
                            text: root.isEnabled ? Theme.iconCheck : Theme.iconTimes
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: root.isEnabled ? Theme.accentSuccess : Theme.accentWarning
                        }
                        Text {
                            text: root.isEnabled ? "Shield: ON" : "Shield: OFF"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                    }

                    MouseArea {
                        id: masterMouseArea
                        hoverEnabled: true
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleShield()
                    }
                }

                // Pause / Resume Toggle
                Rectangle {
                    height: 34
                    implicitWidth: pauseBtnRow.implicitWidth + 20
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
                            font.pixelSize: 11
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
                        hoverEnabled: true
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

        // Military-Grade Controls
        Rectangle {
            Layout.fillWidth: true
            height: 52
            radius: Theme.radiusMd
            color: Theme.bgSurface
            border.color: Theme.border
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                spacing: 12

                // Self-Integrity Badge
                Rectangle {
                    height: 30
                    implicitWidth: integrityRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: Theme.bgCard
                    border.color: Theme.border
                    border.width: 1
                    RowLayout {
                        id: integrityRow
                        anchors.centerIn: parent
                        spacing: 6
                        Text {
                            text: "\uf023"
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: Theme.accentSuccess
                        }
                        Text {
                            text: "INTEGRITY: " + (root.selfIntegrityHash && root.selfIntegrityHash !== "UNVERIFIED" ? "VERIFIED (" + root.selfIntegrityHash.substring(0, 8) + ")" : "UNVERIFIED")
                            font.family: Theme.monoFont
                            font.pixelSize: 10
                            color: Theme.textMain
                        }
                    }
                }

                // Homograph Radar
                Rectangle {
                    height: 30
                    implicitWidth: homographRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: Theme.bgCard
                    border.color: root.idnHomographDetected ? Theme.accentDanger : Theme.border
                    border.width: 1
                    RowLayout {
                        id: homographRow
                        anchors.centerIn: parent
                        spacing: 6
                        Text {
                            text: "\uf3eb"
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: root.idnHomographDetected ? Theme.accentDanger : Theme.textMuted
                        }
                        Text {
                            text: root.idnHomographDetected ? "PUNYCODE ALERT" : "IDN RADAR CLEAR"
                            font.family: Theme.fontFamily
                            font.pixelSize: 10
                            color: root.idnHomographDetected ? Theme.accentDanger : Theme.textMain
                        }
                    }
                }
                
                Item { Layout.fillWidth: true }

                // Panic Blackout Button
                Rectangle {
                    height: 30
                    implicitWidth: blackoutRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: blackoutMouseArea.containsMouse ? (root.networkBlackoutActive ? Theme.accentWarning : Theme.accentDanger) : Theme.bgCard
                    border.color: root.networkBlackoutActive ? Theme.accentWarning : Theme.accentDanger
                    border.width: 1
                    RowLayout {
                        id: blackoutRow
                        anchors.centerIn: parent
                        spacing: 6
                        Text {
                            text: "\uf071" // Warning icon
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: blackoutMouseArea.containsMouse ? Theme.bgSurface : (root.networkBlackoutActive ? Theme.accentWarning : Theme.accentDanger)
                        }
                        Text {
                            text: root.networkBlackoutActive ? "RESUME NETWORK" : "PANIC BLACKOUT"
                            font.family: Theme.fontFamily
                            font.pixelSize: 10
                            font.bold: true
                            color: blackoutMouseArea.containsMouse ? Theme.bgSurface : (root.networkBlackoutActive ? Theme.accentWarning : Theme.accentDanger)
                        }
                    }
                    MouseArea {
                        id: blackoutMouseArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleBlackout()
                    }
                }

                // USB Armor Toggle
                Rectangle {
                    height: 30
                    implicitWidth: usbRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: usbMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                    border.color: root.usbArmorEnabled ? Theme.accentSuccess : Theme.border
                    border.width: 1
                    RowLayout {
                        id: usbRow
                        anchors.centerIn: parent
                        spacing: 6
                        Text {
                            text: "\uf287" // usb icon
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: root.usbArmorEnabled ? Theme.accentSuccess : Theme.textMain
                        }
                        Text {
                            text: root.usbArmorEnabled ? "USB ARMOR: ON" : "USB ARMOR: OFF"
                            font.family: Theme.fontFamily
                            font.pixelSize: 10
                            font.bold: true
                            color: root.usbArmorEnabled ? Theme.accentSuccess : Theme.textMain
                        }
                    }
                    MouseArea {
                        id: usbMouseArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleUsbArmor()
                    }
                }
            }
        }

        // Main Body
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
                            text: "ZERO-TRUST SYSTEM GUARDS (CLICK TO TOGGLE)"
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
                                color: dohMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
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
                                    id: dohMouseArea
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleDohGuard()
                                }
                            }

                            // AI DGA Classifier
                            Rectangle {
                                Layout.fillWidth: true
                                height: 60
                                radius: Theme.radiusSm
                                color: aiMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                                border.color: root.aiProtection ? Theme.accentSuccess : Theme.border
                                border.width: 1

                                ColumnLayout {
                                    anchors.centerIn: parent
                                    spacing: 4
                                    RowLayout {
                                        spacing: 6
                                        Text { text: Theme.iconBrain; font.family: Theme.iconFont; font.pixelSize: 12; color: root.aiProtection ? Theme.accentSuccess : Theme.textMuted }
                                        Text { text: "AI Heuristics"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.textMain }
                                    }
                                    Text { text: root.aiProtection ? "DGA Active" : "Disabled"; font.family: Theme.monoFont; font.pixelSize: 10; color: Theme.textMuted }
                                }

                                MouseArea {
                                    id: aiMouseArea
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleAi()
                                }
                            }

                            // Kernel Netfilter
                            Rectangle {
                                Layout.fillWidth: true
                                height: 60
                                radius: Theme.radiusSm
                                color: kernelMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
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

                                MouseArea {
                                    id: kernelMouseArea
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleKernel()
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
                            text: "FILTER CATEGORIES (CLICK TO TOGGLE)"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.textMuted
                        }

                        Repeater {
                            model: [
                                { id: "ads", name: "Advertising & Trackers", count: root.countAds, icon: Theme.iconFilter, active: root.catAds },
                                { id: "telemetry", name: "Telemetry & Analytics", count: root.countTelemetry, icon: Theme.iconPulse, active: root.catTelemetry },
                                { id: "malware", name: "Malware & Phishing C2", count: root.countMalware, icon: Theme.iconShield, active: root.catMalware },
                                { id: "popups", name: "Popups & Fake Overlays", count: root.countPopups, icon: Theme.iconTimes, active: root.catPopups },
                                { id: "social", name: "Social Trackers & Widgets", count: root.countSocial, icon: Theme.iconExternal, active: root.catSocial }
                            ]

                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 38
                                radius: Theme.radiusSm
                                color: catMouseArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                                border.color: modelData.active ? Theme.borderLight : Theme.border
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
                                        color: modelData.active ? Theme.accent : Theme.textDim
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.name
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: modelData.active ? Theme.textMain : Theme.textMuted
                                    }

                                    Text {
                                        text: modelData.count.toLocaleString() + " domains"
                                        font.family: Theme.monoFont
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                    }

                                    Rectangle {
                                        width: 38
                                        height: 20
                                        radius: 3
                                        color: modelData.active ? Qt.rgba(Theme.accentSuccess.r, Theme.accentSuccess.g, Theme.accentSuccess.b, 0.2) : Qt.rgba(Theme.textDim.r, Theme.textDim.g, Theme.textDim.b, 0.2)
                                        border.color: modelData.active ? Theme.accentSuccess : Theme.border
                                        border.width: 1

                                        Text {
                                            anchors.centerIn: parent
                                            text: modelData.active ? "ON" : "OFF"
                                            font.family: Theme.monoFont
                                            font.pixelSize: 9
                                            font.bold: true
                                            color: modelData.active ? Theme.accentSuccess : Theme.textDim
                                        }
                                    }
                                }

                                MouseArea {
                                    id: catMouseArea
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleCategory(modelData.id)
                                }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        // Utilities Row (Diagnostic, Flush DNS, Update)
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Rectangle {
                                Layout.fillWidth: true
                                height: 34
                                radius: Theme.radiusSm
                                color: testBtnArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                                border.color: Theme.border
                                border.width: 1

                                RowLayout {
                                    anchors.centerIn: parent
                                    spacing: 6
                                    Text {
                                        text: Theme.iconCheck
                                        font.family: Theme.iconFont
                                        font.pixelSize: 11
                                        color: Theme.accent
                                    }
                                    Text {
                                        text: root.isTesting ? "Testing..." : "Run Test"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        font.bold: true
                                        color: Theme.textMain
                                    }
                                }

                                MouseArea {
                                    id: testBtnArea
                                    hoverEnabled: true
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.testShield()
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                height: 34
                                radius: Theme.radiusSm
                                color: flushBtnArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                                border.color: Theme.border
                                border.width: 1

                                RowLayout {
                                    anchors.centerIn: parent
                                    spacing: 6
                                    Text {
                                        text: Theme.iconPulse
                                        font.family: Theme.iconFont
                                        font.pixelSize: 11
                                        color: Theme.accent
                                    }
                                    Text {
                                        text: "Flush DNS"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        font.bold: true
                                        color: Theme.textMain
                                    }
                                }

                                MouseArea {
                                    id: flushBtnArea
                                    hoverEnabled: true
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.flushDns()
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                height: 34
                                radius: Theme.radiusSm
                                color: updateBtnArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                                border.color: Theme.border
                                border.width: 1

                                RowLayout {
                                    anchors.centerIn: parent
                                    spacing: 6
                                    Text {
                                        text: Theme.iconRefresh
                                        font.family: Theme.iconFont
                                        font.pixelSize: 11
                                        color: Theme.accentSuccess
                                    }
                                    Text {
                                        text: root.isUpdating ? "Updating..." : "Update Rules"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        font.bold: true
                                        color: Theme.textMain
                                    }
                                }

                                MouseArea {
                                    id: updateBtnArea
                                    hoverEnabled: true
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.updateBlocklists()
                                }
                            }
                        }

                        Text {
                            visible: root.testResultMsg.length > 0
                            text: root.testResultMsg
                            font.family: Theme.monoFont
                            font.pixelSize: 10
                            color: Theme.textMuted
                            elide: Text.ElideRight
                            Layout.fillWidth: true
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

                    // Tab Selector: Whitelist vs Blacklist
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        Rectangle {
                            height: 32
                            implicitWidth: wlTabText.implicitWidth + 24
                            radius: Theme.radiusSm
                            color: root.activeListTab === "whitelist" ? Theme.bgCardHover : Theme.bgCard
                            border.color: root.activeListTab === "whitelist" ? Theme.accentSuccess : Theme.border
                            border.width: 1

                            RowLayout {
                                id: wlTabText
                                anchors.centerIn: parent
                                spacing: 6
                                Text {
                                    text: Theme.iconCheck
                                    font.family: Theme.iconFont
                                    font.pixelSize: 10
                                    color: root.activeListTab === "whitelist" ? Theme.accentSuccess : Theme.textMuted
                                }
                                Text {
                                    text: "Whitelist (" + root.whitelist.length + ")"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    font.bold: root.activeListTab === "whitelist"
                                    color: root.activeListTab === "whitelist" ? Theme.textMain : Theme.textMuted
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.activeListTab = "whitelist"
                            }
                        }

                        Rectangle {
                            height: 32
                            implicitWidth: blTabText.implicitWidth + 24
                            radius: Theme.radiusSm
                            color: root.activeListTab === "blacklist" ? Theme.bgCardHover : Theme.bgCard
                            border.color: root.activeListTab === "blacklist" ? Theme.accentDanger : Theme.border
                            border.width: 1

                            RowLayout {
                                id: blTabText
                                anchors.centerIn: parent
                                spacing: 6
                                Text {
                                    text: Theme.iconTimes
                                    font.family: Theme.iconFont
                                    font.pixelSize: 10
                                    color: root.activeListTab === "blacklist" ? Theme.accentDanger : Theme.textMuted
                                }
                                Text {
                                    text: "Custom Blacklist (" + root.blacklist.length + ")"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    font.bold: root.activeListTab === "blacklist"
                                    color: root.activeListTab === "blacklist" ? Theme.textMain : Theme.textMuted
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.activeListTab = "blacklist"
                            }
                        }

                        Item { Layout.fillWidth: true }
                    }

                    // Add Domain Field
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

                                BoundedTextInput {
                                    id: addInput
                                    Layout.fillWidth: true
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 12
                                    color: Theme.textMain
                                    verticalAlignment: TextEdit.AlignVCenter
                                    placeholderText: root.activeListTab === "whitelist"
                                                      ? "Enter domain to trust (e.g. tracking.example.com)..."
                                                      : "Enter domain to sinkhole (e.g. ads.annoying.com)..."
                                    placeholderTextColor: Theme.textDim
                                    maxLength: 256
                                    onAccepted: {
                                        if (root.activeListTab === "whitelist") {
                                            root.addWhitelist(text);
                                        } else {
                                            root.addBlacklist(text);
                                        }
                                        text = "";
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
                                color: root.activeListTab === "whitelist" ? Theme.accentSuccess : Theme.accentDanger
                            }

                            MouseArea {
                                id: addBtnArea
                                hoverEnabled: true
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (root.activeListTab === "whitelist") {
                                        root.addWhitelist(addInput.text);
                                    } else {
                                        root.addBlacklist(addInput.text);
                                    }
                                    addInput.text = "";
                                }
                            }
                        }
                    }

                    // Domain List View
                    ListView {
                        id: domainListView
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 6
                        model: root.activeListTab === "whitelist" ? root.whitelist : root.blacklist

                        delegate: Rectangle {
                            width: domainListView.width
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
                                    text: root.activeListTab === "whitelist" ? Theme.iconCheck : Theme.iconTimes
                                    font.family: Theme.iconFont
                                    font.pixelSize: 11
                                    color: root.activeListTab === "whitelist" ? Theme.accentSuccess : Theme.accentDanger
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
                                        hoverEnabled: true
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: {
                                            if (root.activeListTab === "whitelist") {
                                                root.removeWhitelist(modelData);
                                            } else {
                                                root.removeBlacklist(modelData);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Text {
                            anchors.centerIn: parent
                            visible: (root.activeListTab === "whitelist" ? root.whitelist.length : root.blacklist.length) === 0
                            text: root.activeListTab === "whitelist"
                                  ? "No custom domain whitelist overrides defined.\nAll 470k+ community rules applied."
                                  : "No custom blacklist domains defined.\nEnter a domain above to sinkhole it."
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
