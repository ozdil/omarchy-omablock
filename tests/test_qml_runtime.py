"""Loads the shipped QML under PySide6 with stand-ins for the Quickshell types.

Catches what qmllint cannot: QML that fails to instantiate (unknown types, invalid
signal overrides), the EngineClient action queue and refresh coalescing, and how
MainWindow reports engine exit codes. Skipped when PySide6 is not installed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB = os.path.join(REPO, "tests", "qml", "quickshell_stub.py")

try:
    import PySide6.QtQml  # noqa: F401
    import PySide6.QtGui  # noqa: F401

    HAVE_PYSIDE = True
except Exception:  # ImportError, or a missing libEGL/libGL
    HAVE_PYSIDE = False

FAKE_ENGINE = """#!/bin/bash
# Records each call; --json prints a status, the other options exit as named
echo "$*" >> "$(dirname "$0")/calls.log"
case "$1" in
  --json) sleep 0.2; printf '%s' "$FAKE_STATUS";;
  --bad) sleep 0.1; exit 2;;
  --fail) sleep 0.1; exit 1;;
  --whitelist-add) sleep 0.1; [ "$2" = "nohelper.example" ] && exit 4; exit 0;;
  --blacklist-add) sleep 0.1; case "$2" in *" "*) exit 2;; esac;;
  *) sleep 0.1;;
esac
"""

STATUS = {
    "enabled": True,
    "blocking_level": "ultimate",
    "active_rules": 1234,
    "total_rules": 79662,
    "doh_prevention": True,
    "ai_protection": True,
    "kernel_status": {"is_active": True},
    "whitelist": ["example.org"],
    "blacklist": [],
    "categories": {"ads": True, "telemetry": True, "malware": True, "popups": False, "social": True},
    "category_counts": {"ads": 10, "telemetry": 2, "malware": 3, "popups": 4, "social": 5},
    "idn_homograph_detected": True,
    "pause_remaining_secs": 0,
}


@unittest.skipUnless(HAVE_PYSIDE, "PySide6 is not available")
class QmlRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="omablock_qml_")
        shutil.copytree(os.path.join(REPO, "qml"), os.path.join(self.tmp, "qml"))
        for name in ("omablock-engine", "omablock-status"):
            path = os.path.join(self.tmp, name)
            with open(path, "w") as f:
                f.write(FAKE_ENGINE if name == "omablock-engine" else '#!/bin/bash\nexec "$(dirname "$0")/omablock-engine" --json\n')
            os.chmod(path, 0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_qml(self, body):
        driver = os.path.join(self.tmp, "driver.qml")
        with open(driver, "w") as f:
            f.write(textwrap.dedent(body))
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen", HOME=self.tmp, FAKE_STATUS=json.dumps(STATUS))
        proc = subprocess.run(
            [sys.executable, STUB, driver], cwd=self.tmp, env=env, capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr
        problems = [l for l in output.splitlines() if l.startswith(("QMLWARN", "LOAD FAILED", "TIMEOUT")) or "qt.qml" in l]
        self.assertEqual(problems, [], output)
        results = [l.split("RESULT ", 1)[1] for l in output.splitlines() if "RESULT " in l]
        self.assertTrue(results, output)
        with open(os.path.join(self.tmp, "calls.log")) as f:
            calls = f.read().split("\n")
        return json.loads(results[-1]), [c for c in calls if c]

    def test_engine_client_queues_actions_and_coalesces_refreshes(self):
        result, calls = self.run_qml(f"""
            import QtQuick
            import "file://{self.tmp}/qml"
            Item {{
                id: root
                property var finished: []
                property int statuses: 0
                EngineClient {{
                    id: engine
                    statusCommand: ["{self.tmp}/omablock-engine", "--json"]
                    onStatusReceived: (d) => root.statuses++
                    onActionFinished: (code, msg) => root.finished.push(code + ":" + msg)
                }}
                Component.onCompleted: {{
                    engine.refresh(); engine.refresh(); engine.refresh();
                    engine.runAction(["{self.tmp}/omablock-engine", "--a"], "A");
                    engine.runAction(["{self.tmp}/omablock-engine", "--bad"], "B");
                    engine.runAction(["{self.tmp}/omablock-engine", "--fail"], "C");
                }}
                Timer {{ interval: 3000; running: true; onTriggered: {{
                    console.log("RESULT " + JSON.stringify({{ finished: root.finished, statuses: root.statuses }}));
                    Qt.quit();
                }} }}
            }}
        """)
        self.assertEqual(result["finished"], ["0:A", "2:B", "1:C"])
        actions = [c for c in calls if c != "--json"]
        self.assertEqual(actions, ["--a", "--bad", "--fail"])
        # Three refreshes while one runs become one re-run, plus the refresh after the queue drains
        self.assertLessEqual(calls.count("--json"), 3)
        self.assertGreaterEqual(result["statuses"], 2)

    def test_main_window_applies_status_and_reports_exit_codes(self):
        result, calls = self.run_qml(f"""
            import QtQuick
            import QtQuick.Window
            Window {{
                width: 1200; height: 900; visible: true
                Loader {{ id: ld; anchors.fill: parent; source: "file://{self.tmp}/qml/MainWindow.qml" }}
                property var seen: ({{}})
                Timer {{ interval: 1500; running: true; onTriggered: {{
                    var w = ld.item;
                    seen.loaded = !!w;
                    seen.level = w.blockingLevel;
                    seen.activeRules = w.activeRules;
                    seen.doh = w.dohPrevention;
                    seen.kernel = w.kernelActive;
                    seen.idn = w.idnHomographDetected;
                    seen.whitelist = w.whitelist;
                    w.addBlacklist("bad domain");
                }} }}
                Timer {{ interval: 2500; running: true; onTriggered: {{
                    seen.rejectMsg = ld.item.testResultMsg;
                    ld.item.addWhitelist("nohelper.example");
                }} }}
                Timer {{ interval: 3500; running: true; onTriggered: {{
                    seen.helperMsg = ld.item.testResultMsg;
                    console.log("RESULT " + JSON.stringify(seen));
                    Qt.quit();
                }} }}
            }}
        """)
        self.assertTrue(result["loaded"])
        self.assertEqual(result["level"], "ultimate")
        self.assertEqual(result["activeRules"], 1234)
        self.assertTrue(result["doh"] and result["kernel"] and result["idn"])
        self.assertEqual(result["whitelist"], ["example.org"])
        self.assertIn("--blacklist-add bad domain", calls)
        self.assertIn("Rejected", result["rejectMsg"])
        self.assertIn("system helper", result["helperMsg"])


if __name__ == "__main__":
    unittest.main()
