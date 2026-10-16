import QtQuick
import Quickshell.Io

// Shared omablock-engine plumbing for Panel.qml and MainWindow.qml:
// - status polling with a coalesced re-run when a refresh arrives mid-poll
// - a FIFO action queue (Quickshell ignores `running = true` on a running Process)
// - per-action exit codes, so callers only report success when the engine succeeded
Item {
    id: client

    // Command that prints the status JSON, e.g. [enginePath, "--json"]
    property var statusCommand: []

    property var actionQueue: []
    property bool pendingRefresh: false
    property string currentActionMsg: ""

    signal statusReceived(var data)
    // exitCode: 0 ok, 1 failed (e.g. privileged sync), 2 rejected input
    signal actionFinished(int exitCode, string okMsg)

    visible: false
    width: 0
    height: 0

    function refresh() {
        if (statusProc.running) {
            client.pendingRefresh = true;
        } else {
            statusProc.running = true;
        }
    }

    function runAction(cmd, okMsg) {
        client.actionQueue.push({ cmd: cmd, okMsg: okMsg || "" });
        if (!actionProc.running)
            client.startNextAction();
    }

    function startNextAction() {
        if (client.actionQueue.length === 0) {
            client.refresh();
            return;
        }
        var next = client.actionQueue.shift();
        client.currentActionMsg = next.okMsg;
        actionProc.command = next.cmd;
        actionProc.running = true;
    }

    function stop() {
        client.actionQueue = [];
        client.pendingRefresh = false;
        if (statusProc.running)
            statusProc.running = false;
        if (actionProc.running)
            actionProc.running = false;
    }

    Process {
        id: statusProc
        command: client.statusCommand
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                var d;
                try {
                    d = JSON.parse(String(text || "{}").slice(0, 131072));
                } catch (e) {
                    console.warn("OmaBlock: unreadable engine status:", e);
                    return;
                }
                client.statusReceived(d);
            }
        }
        onExited: {
            if (client.pendingRefresh) {
                client.pendingRefresh = false;
                statusProc.running = true;
            }
        }
    }

    Process {
        id: actionProc
        onExited: (exitCode) => {
            var msg = client.currentActionMsg;
            client.currentActionMsg = "";
            client.actionFinished(exitCode, msg);
            client.startNextAction();
        }
    }
}
