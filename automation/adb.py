from __future__ import annotations

from pathlib import Path
import re
import shlex
import subprocess
import time

from .models import UISnapshot, parse_ui_xml, screen_signature


class ADBError(RuntimeError):
    pass


class ADBClient:
    def __init__(self, serial: str, adb_path: str = "adb", timeout: float = 20.0):
        self.serial = serial
        self.adb_path = adb_path
        self.timeout = timeout

    def _command(self, args: list[str]) -> list[str]:
        return [self.adb_path, "-s", self.serial, *args]

    def run(self, args: list[str], *, binary: bool = False, timeout: float | None = None) -> str | bytes:
        process = subprocess.run(
            self._command(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=not binary,
            timeout=timeout or self.timeout,
            check=False,
        )
        if process.returncode != 0:
            stderr = process.stderr.decode("utf-8", errors="replace") if binary else process.stderr
            raise ADBError(f"ADB command failed ({process.returncode}): {' '.join(args)}\n{stderr.strip()}")
        return process.stdout

    def ensure_device(self) -> None:
        state = str(self.run(["get-state"])).strip()
        if state != "device":
            raise ADBError(f"Device {self.serial!r} is not ready: {state!r}")

    def force_stop(self, package: str) -> None:
        self.run(["shell", "am", "force-stop", package])

    def current_focus(self) -> tuple[str | None, str | None]:
        output = str(self.run(["shell", "dumpsys", "window", "windows"], timeout=30))
        patterns = [
            r"mCurrentFocus=.*?\s([\w.]+)/([\w.$]+)",
            r"mFocusedApp=.*?\s([\w.]+)/([\w.$]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1), f"{match.group(1)}/{match.group(2)}"

        activity_output = str(self.run(["shell", "dumpsys", "activity", "activities"], timeout=30))
        match = re.search(
            r"(?:m|top)?ResumedActivity:.*?\s(?:u\d+\s+)?([\w.]+)/([\w.$]+)",
            activity_output,
        )
        if match:
            return match.group(1), f"{match.group(1)}/{match.group(2)}"
        return None, None

    def dump_ui(self) -> str:
        remote = "/sdcard/codex_runtime_ui.xml"
        self.run(["shell", "uiautomator", "dump", remote], timeout=30)
        output = bytes(self.run(["exec-out", "cat", remote], binary=True, timeout=30))
        text = output.decode("utf-8", errors="replace")
        start = text.find("<?xml")
        if start == -1:
            raise ADBError("UIAutomator did not return XML")
        return text[start:]

    def snapshot(self) -> UISnapshot:
        package, activity = self.current_focus()
        xml = self.dump_ui()
        nodes = parse_ui_xml(xml)
        if package is None:
            package = next((node.package for node in nodes if node.package), None)
        return UISnapshot(
            activity=activity,
            foreground_package=package,
            xml=xml,
            nodes=nodes,
            signature=screen_signature(activity, nodes),
        )

    def screenshot(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(bytes(self.run(["exec-out", "screencap", "-p"], binary=True, timeout=30)))

    def tap(self, x: int, y: int) -> None:
        self.run(["shell", "input", "tap", str(x), str(y)])

    def back(self) -> None:
        self.run(["shell", "input", "keyevent", "KEYCODE_BACK"])

    def scroll_down(self, bounds: tuple[int, int, int, int]) -> None:
        x1, y1, x2, y2 = bounds
        x = (x1 + x2) // 2
        start_y = y1 + int((y2 - y1) * 0.78)
        end_y = y1 + int((y2 - y1) * 0.25)
        self.run(
            ["shell", "input", "swipe", str(x), str(start_y), str(x), str(end_y), "350"]
        )

    def input_text(self, value: str) -> None:
        # `adb shell input text` uses %s for spaces and passes through a device
        # shell. Quote the complete argument and keep fixtures test-only.
        encoded = value.replace(" ", "%s")
        self.run(["shell", "input", "text", shlex.quote(encoded)])

    def wait_for_stable_ui(
        self,
        *,
        timeout: float = 6.0,
        interval: float = 0.6,
        stable_samples: int = 2,
    ) -> UISnapshot:
        deadline = time.monotonic() + timeout
        last: UISnapshot | None = None
        stable = 0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                current = self.snapshot()
                if last is not None and current.signature == last.signature:
                    stable += 1
                else:
                    stable = 0
                last = current
                if stable >= stable_samples:
                    return current
            except Exception as exc:  # UI can be between windows for a moment.
                last_error = exc
            time.sleep(interval)
        if last is not None:
            return last
        raise ADBError(f"UI did not become available: {last_error}")
