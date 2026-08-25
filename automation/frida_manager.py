from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from typing import Any


class FridaManagerError(RuntimeError):
    pass


class FridaManager:
    def __init__(
        self,
        *,
        serial: str,
        package: str,
        script_path: Path,
        log_path: Path,
        ready_timeout: float = 35.0,
    ):
        self.serial = serial
        self.package = package
        self.script_path = script_path
        self.log_path = log_path
        self.ready_timeout = ready_timeout
        self.device: Any = None
        self.pid: int | None = None
        self.session: Any = None
        self.script: Any = None
        self._ready = threading.Event()
        self._messages: list[str] = []
        self._lock = threading.Lock()
        self._log_file: Any = None
        self._fatal_error: str | None = None

    @staticmethod
    def _import_frida() -> Any:
        try:
            import frida  # type: ignore
        except ImportError as exc:
            raise FridaManagerError(
                "The Python frida package is missing. Run this orchestrator with ./venv/bin/python."
            ) from exc
        return frida

    @staticmethod
    def _agent_source(user_source: str) -> str:
        # Frida 17 moved language bridges out of GumJS. frida-tools' REPL loads
        # this same bridge lazily; raw Python create_script() callers must load
        # it themselves.
        try:
            import frida_tools  # type: ignore
        except ImportError as exc:
            raise FridaManagerError("frida-tools is required to load the Java bridge") from exc
        bridge_path = Path(frida_tools.__file__).parent / "bridges" / "java.js"
        if not bridge_path.is_file():
            raise FridaManagerError(f"Frida Java bridge was not found: {bridge_path}")
        bridge_source = bridge_path.read_text(encoding="utf-8")
        bridge_wrapper = (
            "(function () {\n"
            + bridge_source
            + "\nObject.defineProperty(globalThis, 'Java', { enumerable: true, configurable: true, value: bridge });\n"
            + "return bridge;\n})();"
        )
        bootstrap = "Script.evaluate('/frida/bridges/java.js', " + json.dumps(bridge_wrapper) + ");\n"
        return bootstrap + user_source

    def _find_device(self, frida: Any) -> Any:
        try:
            return frida.get_device(self.serial, timeout=10)
        except Exception:
            devices = frida.enumerate_devices()
            for device in devices:
                if device.id == self.serial:
                    return device
            available = ", ".join(f"{item.id} ({item.type})" for item in devices)
            raise FridaManagerError(
                f"Frida device {self.serial!r} was not found. Available devices: {available or 'none'}"
            )

    def start(self) -> None:
        if not self.script_path.is_file():
            raise FridaManagerError(f"Frida script does not exist: {self.script_path}")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file = self.log_path.open("w", encoding="utf-8", buffering=1)
        frida = self._import_frida()
        try:
            self.device = self._find_device(frida)
            self.pid = int(self.device.spawn([self.package]))
            self.session = self.device.attach(self.pid)
            source = self._agent_source(self.script_path.read_text(encoding="utf-8"))
            self.script = self.session.create_script(source)
            self.script.set_log_handler(self._on_log)
            self.script.on("message", self._on_message)
            self.script.load()
            self.device.resume(self.pid)
            if not self._ready.wait(self.ready_timeout):
                detail = self._fatal_error or "READY event was not observed"
                raise FridaManagerError(f"Frida tracer did not become ready: {detail}")
        except Exception:
            self.stop()
            raise

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        message_type = message.get("type")
        if message_type == "log":
            line = str(message.get("payload", ""))
        elif message_type == "error":
            line = "[FRIDA_ERROR] " + json.dumps(message, ensure_ascii=False)
            self._fatal_error = str(message.get("description") or message.get("stack") or message)
        else:
            envelope: dict[str, Any] = {"message": message}
            if data is not None:
                envelope["dataLength"] = len(data)
            line = "[FRIDA_MESSAGE] " + json.dumps(envelope, ensure_ascii=False)

        self._record_line(line)

    def _on_log(self, level: str, text: str) -> None:
        for raw_line in str(text).splitlines() or [""]:
            line = raw_line if raw_line.startswith(("[TRACE] ", "[COMMON] ")) else f"[FRIDA_LOG {level}] {raw_line}"
            self._record_line(line)

    def _record_line(self, line: str) -> None:
        with self._lock:
            self._messages.append(line)
            if self._log_file is not None:
                self._log_file.write(line + "\n")

        if line.startswith("[TRACE] "):
            try:
                record = json.loads(line[len("[TRACE] ") :])
                if record.get("stage") == "READY":
                    self._ready.set()
            except json.JSONDecodeError:
                pass

    def _exports(self) -> Any:
        if self.script is None:
            raise FridaManagerError("Frida script is not running")
        return self.script.exports_sync

    def get_summary(self) -> dict[str, Any]:
        result = self._exports().get_common_summary()
        if not isinstance(result, dict):
            raise FridaManagerError(f"Unexpected common summary result: {type(result).__name__}")
        return result

    def reset_summary(self, label: str) -> dict[str, Any]:
        result = self._exports().reset_common_summary(label)
        if not isinstance(result, dict):
            raise FridaManagerError(f"Unexpected reset summary result: {type(result).__name__}")
        if result.get("status") == "NOT_READY":
            raise FridaManagerError(f"Tracer summary is not ready: {result}")
        return result

    def mark_user_action(self, kind: str, target: str) -> dict[str, Any]:
        result = self._exports().mark_user_action(kind, target)
        if not isinstance(result, dict):
            raise FridaManagerError(f"Unexpected user action marker result: {type(result).__name__}")
        if result.get("status") == "NOT_READY":
            raise FridaManagerError(f"Tracer action marker is not ready: {result}")
        return result

    def message_mark(self) -> int:
        with self._lock:
            return len(self._messages)

    def messages_since(self, mark: int) -> list[str]:
        with self._lock:
            return self._messages[mark:]

    def wait_for_quiet(self, quiet_seconds: float = 1.0, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        last_count = self.message_mark()
        quiet_since = time.monotonic()
        while time.monotonic() < deadline:
            time.sleep(0.2)
            count = self.message_mark()
            if count != last_count:
                last_count = count
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= quiet_seconds:
                return

    def stop(self) -> None:
        try:
            if self.script is not None:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass
        self.script = None
        self.session = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    def __enter__(self) -> "FridaManager":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()
