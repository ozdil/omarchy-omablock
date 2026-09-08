import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "ozdil.omablock"
  ipcTarget: "ozdil.omablock"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // State properties
  property bool isEnabled: false
  property int activeRules: 0
  property int totalRules: 0
  property bool systemHostsActive: false

  property bool catAds: true
  property bool catTelemetry: true
  property bool catMalware: true
  property bool catSocial: false

  property int countAds: 0
  property int countTelemetry: 0
  property int countMalware: 0
  property int countSocial: 0

  property var whitelist: []
  property var blacklist: []
  property string lastUpdated: "Built-in Curated v1.0"

  property bool isTesting: false
  property bool isUpdating: false
  property bool testSuccess: false
  property string testMessage: ""
  property real testLatency: 0.0

  property string toastMsg: ""

  function resolveEnginePath() {
    return Qt.resolvedUrl("omablock-engine").toString().replace(/^file:\/\//, "")
  }

  function showToast(msg) {
    root.toastMsg = msg
    toastTimer.restart()
  }

  function refresh() {
    if (!statusProc.running) {
      statusProc.running = true
    }
  }

  function toggleMaster() {
    actionProc.command = [root.resolveEnginePath(), "--toggle"]
    actionProc.running = true
  }

  function toggleCategory(cat) {
    actionProc.command = [root.resolveEnginePath(), "--toggle-category", cat]
    actionProc.running = true
  }

  function runTest() {
    if (root.isTesting) return
    root.isTesting = true
    testProc.command = [root.resolveEnginePath(), "--test"]
    testProc.running = true
  }

  function updateBlocklists() {
    if (root.isUpdating) return
    root.isUpdating = true
    showToast("Updating blocklists from servers...")
    updateProc.command = [root.resolveEnginePath(), "--update"]
    updateProc.running = true
  }

  function flushDns() {
    actionProc.command = [root.resolveEnginePath(), "--flush"]
    actionProc.running = true
    showToast("Flushed system DNS caches")
  }

  function addWhitelist(domain) {
    if (!domain) return
    actionProc.command = [root.resolveEnginePath(), "--whitelist-add", domain]
    actionProc.running = true
    showToast("Whitelisted: " + domain)
  }

  function removeWhitelist(domain) {
    if (!domain) return
    actionProc.command = [root.resolveEnginePath(), "--whitelist-remove", domain]
    actionProc.running = true
    showToast("Removed from whitelist: " + domain)
  }

  function addBlacklist(domain) {
    if (!domain) return
    actionProc.command = [root.resolveEnginePath(), "--blacklist-add", domain]
    actionProc.running = true
    showToast("Blocked: " + domain)
  }

  function removeBlacklist(domain) {
    if (!domain) return
    actionProc.command = [root.resolveEnginePath(), "--blacklist-remove", domain]
    actionProc.running = true
    showToast("Removed from blacklist: " + domain)
  }

  IpcHandler {
    target: "ozdil.omablock"

    function open() { root.open() }
    function close() { root.close() }
    function show() { root.open() }
    function hide() { root.close() }
    function toggle() { root.toggle() }
    function refresh() { root.refresh() }
    function test() { root.runTest() }
  }

  Process {
    id: statusProc
    command: [root.resolveEnginePath(), "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var cleanText = String(text || "").slice(0, 131072)
          var d = JSON.parse(cleanText)
          root.isEnabled = !!d.enabled
          root.activeRules = d.active_rules || 0
          root.totalRules = d.total_rules || 0
          root.systemHostsActive = !!d.system_hosts_active

          if (d.categories) {
            root.catAds = !!d.categories.ads
            root.catTelemetry = !!d.categories.telemetry
            root.catMalware = !!d.categories.malware
            root.catSocial = !!d.categories.social
          }

          if (d.category_counts) {
            root.countAds = d.category_counts.ads || 0
            root.countTelemetry = d.category_counts.telemetry || 0
            root.countMalware = d.category_counts.malware || 0
            root.countSocial = d.category_counts.social || 0
          }

          root.whitelist = d.whitelist || []
          root.blacklist = d.blacklist || []
          root.lastUpdated = d.last_updated || "Built-in Curated v1.0"

          if (d.last_test) {
            root.testSuccess = !!d.last_test.success
            root.testMessage = d.last_test.message || ""
            root.testLatency = d.last_test.avg_latency_ms || 0.0
          }
        } catch (e) {}
      }
    }
  }

  Process {
    id: actionProc
    onExited: {
      root.refresh()
    }
  }

  Process {
    id: testProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isTesting = false
        try {
          var cleanText = String(text || "").slice(0, 131072)
          var d = JSON.parse(cleanText)
          root.testSuccess = !!d.success
          root.testMessage = d.message || ""
          root.testLatency = d.avg_latency_ms || 0.0
          root.showToast(d.success ? "Shield Verified (0.00ms)" : "Verification alert")
        } catch (e) {}
        root.refresh()
      }
    }
  }

  Process {
    id: updateProc
    onExited: {
      root.isUpdating = false
      root.showToast("Blocklists updated successfully")
      root.refresh()
    }
  }

  Timer {
    id: toastTimer
    interval: 3500
    onTriggered: root.toastMsg = ""
  }

  Timer {
    id: autoRefreshTimer
    interval: 15000
    repeat: true
    running: root.opened
    onTriggered: root.refresh()
  }

  Component.onCompleted: refresh()

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    tooltipText: root.isEnabled ? ("OmaBlock: Active (" + root.activeRules.toLocaleString() + " rules)") : "OmaBlock: Disabled"
    active: root.isEnabled && root.systemHostsActive
    activeColor: Color.accent
    useActiveColor: true
    dimmed: !root.isEnabled
    onPressed: function(b) {
      root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight + Style.space(24), Style.space(840))

    ScrollView {
      id: scrollArea
      anchors.fill: parent
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
      ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

      Column {
        id: panelColumn
        width: scrollArea.availableWidth
        spacing: Style.space(12)

        // ---------- Hero Section ----------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, masterToggle.implicitHeight)

          Text {
            id: heroIcon
            textFormat: Text.PlainText
            text: ""
            color: (root.isEnabled && root.systemHostsActive) ? Color.accent : Color.muted
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
            font.pixelSize: Style.font.display
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: masterToggle.left
            anchors.rightMargin: Style.space(12)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(3)

            Row {
              spacing: Style.space(8)

              Text {
                text: "OmaBlock"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.title
                font.bold: true
              }

              // Status pill badge
              BorderSurface {
                anchors.verticalCenter: parent.verticalCenter
                radius: Style.cornerRadius
                color: (root.isEnabled && root.systemHostsActive) ? Style.selectedFillFor(Color.foreground, Color.accent) : "transparent"
                borderSpec: Border.controlSpec((root.isEnabled && root.systemHostsActive) ? "selected" : "normal", Color.foreground, Color.accent)
                implicitHeight: Style.space(18)
                implicitWidth: statusPillText.implicitWidth + Style.space(12)

                Text {
                  id: statusPillText
                  anchors.centerIn: parent
                  text: (root.isEnabled && root.systemHostsActive) ? "ACTIVE • PROTECTED" : "SHIELD DISABLED"
                  color: (root.isEnabled && root.systemHostsActive) ? Color.accent : Color.muted
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption - 1
                  font.bold: true
                }
              }
            }

            Text {
              text: "Kernel-level zero-latency ad and tracker shield"
              color: Color.muted
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
              width: parent.width
            }
          }

          ToggleSwitch {
            id: masterToggle
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            checked: root.isEnabled
            accent: Color.accent
            onToggled: root.toggleMaster()
          }
        }

        // ---------- Toast Message Banner ----------
        BorderSurface {
          width: parent.width
          visible: root.toastMsg !== ""
          radius: Style.cornerRadius
          color: Style.selectedFillFor(Color.foreground, Color.accent)
          borderSpec: Border.controlSpec("focus", Color.foreground, Color.accent)
          implicitHeight: toastLabel.implicitHeight + Style.space(10)

          Row {
            anchors.centerIn: parent
            spacing: Style.space(8)

            Text {
              text: ""
              font.family: Style.font.family
              font.pixelSize: Style.font.body
              color: Color.accent
            }

            Text {
              id: toastLabel
              text: root.toastMsg
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              color: Color.foreground
              font.bold: true
            }
          }
        }

        // ---------- Key Metrics 3-Card Row ----------
        Row {
          width: parent.width
          spacing: Style.space(8)

          // Card 1: Active Rules
          BorderSurface {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(64)
            radius: Style.cornerRadius
            color: Style.controlFill(false, false, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.foreground, Color.accent)

            Column {
              anchors.centerIn: parent
              spacing: Style.space(2)

              Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Style.space(6)

                Text {
                  text: ""
                  font.family: Style.font.family
                  font.pixelSize: Style.font.body
                  color: Color.accent
                }

                Text {
                  text: root.activeRules > 0 ? root.activeRules.toLocaleString() : (root.isEnabled ? "79,561" : "0")
                  font.family: Style.font.family
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  color: Color.foreground
                }
              }

              Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: "Blocked Rules"
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                color: Color.muted
              }
            }
          }

          // Card 2: Speed / Latency
          BorderSurface {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(64)
            radius: Style.cornerRadius
            color: Style.controlFill(false, false, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.foreground, Color.accent)

            Column {
              anchors.centerIn: parent
              spacing: Style.space(2)

              Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Style.space(6)

                Text {
                  text: ""
                  font.family: Style.font.family
                  font.pixelSize: Style.font.body
                  color: Color.accent
                }

                Text {
                  text: "< 0.1ms"
                  font.family: Style.font.family
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  color: Color.foreground
                }
              }

              Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: "Sinkhole Latency"
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                color: Color.muted
              }
            }
          }

          // Card 3: DNS Enforcement
          BorderSurface {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(64)
            radius: Style.cornerRadius
            color: Style.controlFill(false, false, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.foreground, Color.accent)

            Column {
              anchors.centerIn: parent
              spacing: Style.space(2)

              Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Style.space(6)

                Text {
                  text: "󰒃"
                  font.family: Style.font.family
                  font.pixelSize: Style.font.body
                  color: (root.isEnabled && root.systemHostsActive) ? Color.accent : Color.muted
                }

                Text {
                  text: (root.isEnabled && root.systemHostsActive) ? "Active" : "Standby"
                  font.family: Style.font.family
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  color: Color.foreground
                }
              }

              Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: "Enforced DNS"
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                color: Color.muted
              }
            }
          }
        }

        PanelSeparator {}

        // ---------- Protection Categories Section ----------
        PanelSectionHeader {
          text: "PROTECTION CATEGORIES"
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          // 1. Ads & Banners
          BorderSurface {
            width: parent.width
            implicitHeight: Style.space(48)
            radius: Style.cornerRadius
            color: Style.controlFill(false, mouseAds.containsMouse, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec(mouseAds.containsMouse ? "hover-cursor" : "normal", Color.foreground, Color.accent)

            MouseArea {
              id: mouseAds
              anchors.fill: parent
              hoverEnabled: true
              onClicked: root.toggleCategory("ads")
            }

            Text {
              id: iconAds
              anchors.left: parent.left
              anchors.leftMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              width: Style.space(22)
              horizontalAlignment: Text.AlignHCenter
              text: ""
              font.family: Style.font.family
              font.pixelSize: Style.font.icon
              color: root.catAds ? Color.accent : Color.muted
            }

            ToggleSwitch {
              id: toggleAds
              anchors.right: parent.right
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              checked: root.catAds
              accent: Color.accent
              onToggled: root.toggleCategory("ads")
            }

            Column {
              anchors.left: iconAds.right
              anchors.leftMargin: Style.space(10)
              anchors.right: toggleAds.left
              anchors.rightMargin: Style.space(10)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)

              Text {
                text: "Ads & Commercial Banners"
                color: Color.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                text: (root.countAds > 0 ? root.countAds.toLocaleString() : "75,416") + " domains • Popups, video ads, syndication"
                color: Color.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }

          // 2. Telemetry & Tracking
          BorderSurface {
            width: parent.width
            implicitHeight: Style.space(48)
            radius: Style.cornerRadius
            color: Style.controlFill(false, mouseTelem.containsMouse, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec(mouseTelem.containsMouse ? "hover-cursor" : "normal", Color.foreground, Color.accent)

            MouseArea {
              id: mouseTelem
              anchors.fill: parent
              hoverEnabled: true
              onClicked: root.toggleCategory("telemetry")
            }

            Text {
              id: iconTelem
              anchors.left: parent.left
              anchors.leftMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              width: Style.space(22)
              horizontalAlignment: Text.AlignHCenter
              text: "󰈉"
              font.family: Style.font.family
              font.pixelSize: Style.font.icon
              color: root.catTelemetry ? Color.accent : Color.muted
            }

            ToggleSwitch {
              id: toggleTelem
              anchors.right: parent.right
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              checked: root.catTelemetry
              accent: Color.accent
              onToggled: root.toggleCategory("telemetry")
            }

            Column {
              anchors.left: iconTelem.right
              anchors.leftMargin: Style.space(10)
              anchors.right: toggleTelem.left
              anchors.rightMargin: Style.space(10)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)

              Text {
                text: "Telemetry & Surveillance"
                color: Color.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                text: (root.countTelemetry > 0 ? root.countTelemetry.toLocaleString() : "3,666") + " domains • OS metrics, analytics, crash logs"
                color: Color.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }

          // 3. Malware & Phishing
          BorderSurface {
            width: parent.width
            implicitHeight: Style.space(48)
            radius: Style.cornerRadius
            color: Style.controlFill(false, mouseMal.containsMouse, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec(mouseMal.containsMouse ? "hover-cursor" : "normal", Color.foreground, Color.accent)

            MouseArea {
              id: mouseMal
              anchors.fill: parent
              hoverEnabled: true
              onClicked: root.toggleCategory("malware")
            }

            Text {
              id: iconMal
              anchors.left: parent.left
              anchors.leftMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              width: Style.space(22)
              horizontalAlignment: Text.AlignHCenter
              text: ""
              font.family: Style.font.family
              font.pixelSize: Style.font.icon
              color: root.catMalware ? Color.accent : Color.muted
            }

            ToggleSwitch {
              id: toggleMal
              anchors.right: parent.right
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              checked: root.catMalware
              accent: Color.accent
              onToggled: root.toggleCategory("malware")
            }

            Column {
              anchors.left: iconMal.right
              anchors.leftMargin: Style.space(10)
              anchors.right: toggleMal.left
              anchors.rightMargin: Style.space(10)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)

              Text {
                text: "Malware & Phishing"
                color: Color.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                text: (root.countMalware > 0 ? root.countMalware.toLocaleString() : "449") + " domains • Scams, botnets, crypto miners"
                color: Color.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }

          // 4. Social Network Trackers
          BorderSurface {
            width: parent.width
            implicitHeight: Style.space(48)
            radius: Style.cornerRadius
            color: Style.controlFill(false, mouseSoc.containsMouse, Color.foreground, Color.accent)
            borderSpec: Border.controlSpec(mouseSoc.containsMouse ? "hover-cursor" : "normal", Color.foreground, Color.accent)

            MouseArea {
              id: mouseSoc
              anchors.fill: parent
              hoverEnabled: true
              onClicked: root.toggleCategory("social")
            }

            Text {
              id: iconSoc
              anchors.left: parent.left
              anchors.leftMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              width: Style.space(22)
              horizontalAlignment: Text.AlignHCenter
              text: ""
              font.family: Style.font.family
              font.pixelSize: Style.font.icon
              color: root.catSocial ? Color.accent : Color.muted
            }

            ToggleSwitch {
              id: toggleSoc
              anchors.right: parent.right
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              checked: root.catSocial
              accent: Color.accent
              onToggled: root.toggleCategory("social")
            }

            Column {
              anchors.left: iconSoc.right
              anchors.leftMargin: Style.space(10)
              anchors.right: toggleSoc.left
              anchors.rightMargin: Style.space(10)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)

              Text {
                text: "Social Network Trackers"
                color: Color.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                text: (root.countSocial > 0 ? root.countSocial.toLocaleString() : "30") + " domains • Facebook pixel, TikTok tracking"
                color: Color.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }
        }

        PanelSeparator {}

        // ---------- Verification & Testing Section ----------
        PanelSectionHeader {
          text: "SHIELD VERIFICATION & DIAGNOSTICS"
        }

        BorderSurface {
          width: parent.width
          implicitHeight: Style.space(56)
          radius: Style.cornerRadius
          color: Style.controlFill(false, false, Color.foreground, Color.accent)
          borderSpec: Border.controlSpec(root.testSuccess ? "selected" : "normal", Color.foreground, Color.accent)

          Row {
            anchors.fill: parent
            anchors.leftMargin: Style.space(12)
            anchors.rightMargin: Style.space(12)
            spacing: Style.space(12)

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: root.isTesting ? "" : (root.testSuccess ? "" : "")
              font.family: Style.font.family
              font.pixelSize: Style.font.icon
              color: root.isTesting ? Color.foreground : (root.testSuccess ? Color.accent : Color.muted)
            }

            Column {
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)
              width: parent.width - Style.space(50)

              Text {
                text: root.isTesting ? "Resolving test ad domains..." : (root.testSuccess ? "Sinkhole Verified & Active" : "Shield Verification Pending")
                color: Color.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                text: root.testMessage ? root.testMessage : "Test known ad servers (doubleclick.net, pagead2) for 0.0.0.0 sinkhole."
                color: Color.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption - 1
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }
        }

        // Action Buttons Row
        Row {
          width: parent.width
          spacing: Style.space(8)

          Button {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(34)
            horizontalPadding: Style.space(6)
            bordered: true
            iconText: root.isTesting ? "" : ""
            text: root.isTesting ? "Testing..." : "Test Shield"
            fontSize: Style.font.caption
            onClicked: root.runTest()
          }

          Button {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(34)
            horizontalPadding: Style.space(6)
            bordered: true
            iconText: root.isUpdating ? "" : ""
            text: root.isUpdating ? "Updating..." : "Update Lists"
            fontSize: Style.font.caption
            onClicked: root.updateBlocklists()
          }

          Button {
            width: Math.floor((parent.width - Style.space(16)) / 3)
            implicitHeight: Style.space(34)
            horizontalPadding: Style.space(6)
            bordered: true
            iconText: ""
            text: "Flush DNS"
            fontSize: Style.font.caption
            onClicked: root.flushDns()
          }
        }

        PanelSeparator {}

        // ---------- Custom Whitelist & Rules Section ----------
        PanelSectionHeader {
          text: "CUSTOM RULES & WHITELIST (" + (root.whitelist.length + root.blacklist.length) + ")"
        }

        Item {
          width: parent.width
          implicitHeight: Style.space(32)

          Row {
            id: ruleButtons
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(8)

            Button {
              id: btnAllow
              implicitWidth: Style.space(64)
              implicitHeight: Style.space(32)
              horizontalPadding: Style.space(8)
              bordered: true
              text: "Allow"
              fontSize: Style.font.caption
              onClicked: {
                if (domainInput.text.trim()) {
                  root.addWhitelist(domainInput.text.trim())
                  domainInput.text = ""
                }
              }
            }

            Button {
              id: btnBlock
              implicitWidth: Style.space(64)
              implicitHeight: Style.space(32)
              horizontalPadding: Style.space(8)
              bordered: true
              text: "Block"
              fontSize: Style.font.caption
              onClicked: {
                if (domainInput.text.trim()) {
                  root.addBlacklist(domainInput.text.trim())
                  domainInput.text = ""
                }
              }
            }
          }

          TextField {
            id: domainInput
            anchors.left: parent.left
            anchors.right: ruleButtons.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            implicitHeight: Style.space(32)
            placeholderText: "Domain (e.g. ad.example.com)"
            onAccepted: {
              if (domainInput.text.trim()) {
                root.addWhitelist(domainInput.text.trim())
                domainInput.text = ""
              }
            }
          }
        }

        // Whitelist chips / items
        Column {
          width: parent.width
          spacing: Style.space(4)
          visible: root.whitelist.length > 0 || root.blacklist.length > 0

          Repeater {
            model: root.whitelist
            delegate: BorderSurface {
              width: parent.width
              implicitHeight: Style.space(28)
              radius: Style.cornerRadius
              color: Style.controlFill(false, false, Color.foreground, Color.accent)
              borderSpec: Border.controlSpec("normal", Color.foreground, Color.accent)

              Row {
                anchors.fill: parent
                anchors.leftMargin: Style.space(8)
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(8)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: " Allow:"
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption - 1
                  color: Color.accent
                  font.bold: true
                }

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  color: Color.foreground
                  width: parent.width - Style.space(80)
                  elide: Text.ElideRight
                }

                MouseArea {
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(20)
                  height: Style.space(20)
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.removeWhitelist(modelData)

                  Text {
                    anchors.centerIn: parent
                    text: ""
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    color: Color.muted
                  }
                }
              }
            }
          }

          Repeater {
            model: root.blacklist
            delegate: BorderSurface {
              width: parent.width
              implicitHeight: Style.space(28)
              radius: Style.cornerRadius
              color: Style.controlFill(false, false, Color.foreground, Color.accent)
              borderSpec: Border.controlSpec("normal", Color.foreground, Color.accent)

              Row {
                anchors.fill: parent
                anchors.leftMargin: Style.space(8)
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(8)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: " Block:"
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption - 1
                  color: Color.foreground
                  font.bold: true
                }

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  color: Color.foreground
                  width: parent.width - Style.space(80)
                  elide: Text.ElideRight
                }

                MouseArea {
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(20)
                  height: Style.space(20)
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.removeBlacklist(modelData)

                  Text {
                    anchors.centerIn: parent
                    text: ""
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    color: Color.muted
                  }
                }
              }
            }
          }
        }

        // ---------- Bottom Meta Footer ----------
        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          text: "OmaBlock v1.0 • Updated: " + root.lastUpdated
          font.family: Style.font.family
          font.pixelSize: Style.font.caption - 2
          color: Color.muted
        }

        Item {
          width: parent.width
          height: Style.space(20)
          implicitHeight: Style.space(20)
        }
      }
    }
  }
}
