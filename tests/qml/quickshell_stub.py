"""Runs a QML file with minimal stand-ins for the Quickshell types OmaBlock uses.

Only what qml/MainWindow.qml, qml/EngineClient.qml, qml/BoundedTextInput.qml and
qml/theme/Theme.qml need: Process (backed by QProcess), StdioCollector, SplitParser,
FileView and the Quickshell.env() singleton. Every QML warning is printed with a
QMLWARN prefix so the caller can fail on it.

Usage: python3 quickshell_stub.py <file.qml>
"""

import os
import sys

from PySide6.QtCore import Property, QObject, QProcess, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine, qmlRegisterSingletonInstance, qmlRegisterType


class StdioCollector(QObject):
    streamFinished = Signal()
    textChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._wait = True

    def _get_text(self):
        return self._text

    text = Property(str, _get_text, notify=textChanged)

    def _get_wait(self):
        return self._wait

    def _set_wait(self, value):
        self._wait = value

    waitForEnd = Property(bool, _get_wait, _set_wait)


class SplitParser(QObject):
    read = Signal(str, arguments=["data"])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._marker = ""

    def _get_marker(self):
        return self._marker

    def _set_marker(self, value):
        self._marker = value

    splitMarker = Property(str, _get_marker, _set_marker)


class Process(QObject):
    runningChanged = Signal()
    commandChanged = Signal()
    stdoutChanged = Signal()
    exited = Signal(int, int, arguments=["exitCode", "exitStatus"])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._command = []
        self._stdout = None
        self._proc = None

    def _get_command(self):
        return self._command

    def _set_command(self, value):
        value = value.toVariant() if hasattr(value, "toVariant") else value
        self._command = [str(x) for x in (value or [])]
        self.commandChanged.emit()

    command = Property("QVariant", _get_command, _set_command, notify=commandChanged)

    def _get_stdout(self):
        return self._stdout

    def _set_stdout(self, value):
        self._stdout = value
        self.stdoutChanged.emit()

    stdout = Property(QObject, _get_stdout, _set_stdout, notify=stdoutChanged)

    def _get_running(self):
        return self._proc is not None

    def _set_running(self, value):
        # Like Quickshell: running = true on a running process is ignored
        if value and self._proc is None and self._command:
            proc = QProcess(self)
            self._proc = proc
            proc.finished.connect(lambda code, status: self._finished(proc, code))
            proc.start(self._command[0], self._command[1:])
            self.runningChanged.emit()
        elif not value and self._proc is not None:
            self._proc.kill()

    running = Property(bool, _get_running, _set_running, notify=runningChanged)

    def _finished(self, proc, code):
        out = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
        self._proc = None
        self.runningChanged.emit()
        if isinstance(self._stdout, SplitParser):
            if out:
                self._stdout.read.emit(out)
        elif isinstance(self._stdout, StdioCollector):
            self._stdout._text = out
            self._stdout.textChanged.emit()
            self._stdout.streamFinished.emit()
        self.exited.emit(code, 0)


class FileView(QObject):
    loaded = Signal()
    fileChanged = Signal()
    pathChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._path = ""
        self._flag = False

    def _get_path(self):
        return self._path

    def _set_path(self, value):
        self._path = value
        self.pathChanged.emit()

    path = Property(str, _get_path, _set_path, notify=pathChanged)

    def _get_flag(self):
        return self._flag

    def _set_flag(self, value):
        self._flag = value

    watchChanges = Property(bool, _get_flag, _set_flag)
    printErrors = Property(bool, _get_flag, _set_flag)

    @Slot(result=str)
    def text(self):
        try:
            with open(self._path, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    @Slot()
    def reload(self):
        pass


class QuickshellSingleton(QObject):
    @Slot(str, result=str)
    def env(self, key):
        return os.environ.get(key, "")


class _ModuleMarker(QObject):
    pass


def main():
    qmlRegisterType(_ModuleMarker, "Quickshell", 1, 0, "QuickshellStubMarker")
    for cls in (Process, StdioCollector, SplitParser, FileView):
        qmlRegisterType(cls, "Quickshell.Io", 1, 0, cls.__name__)
    app = QGuiApplication(sys.argv)
    singleton = QuickshellSingleton()
    qmlRegisterSingletonInstance(QuickshellSingleton, "Quickshell", 1, 0, "Quickshell", singleton)
    engine = QQmlApplicationEngine()
    engine.warnings.connect(lambda warnings: [print("QMLWARN", w.toString(), flush=True) for w in warnings])
    engine.load(QUrl.fromLocalFile(sys.argv[1]))
    if not engine.rootObjects():
        print("LOAD FAILED", flush=True)
        sys.exit(1)
    QTimer.singleShot(20000, lambda: (print("TIMEOUT", flush=True), app.exit(2)))
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
