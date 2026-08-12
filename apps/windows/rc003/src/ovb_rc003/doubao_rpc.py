"""Small adapters for Doubao's native keyboard paths.

Doubao ignores the ``LLKHF_INJECTED`` flag on ordinary Win32 synthetic
keyboard events.  The native RPC functions are retained as a narrow diagnostic
adapter, while the production voice path uses an optional Frida callback hook
to clear that flag inside Doubao's own low-level keyboard callback.  It is
deliberately lazy: importing the bridge must still work when Doubao is not
installed or when tests run off Windows.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import sys
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional, Tuple


DEFAULT_PIPE = r"\\.\pipe\ObricIme\oime-server"
_RPC_DLL_NAME = "rpc.dll"
_IME_SERVICE_NAME = "ImeService.exe"
# The callback is deliberately allow-listed per exact ImeService.exe build.
# Attaching Frida at a guessed address after Doubao updates would be much more
# dangerous than declining the optional integration, especially because this
# callback sits in the global keyboard path.  The second entry is the build
# shipped on 2026-08-10; its RVA was recovered statically from the
# SetWindowsHookExW(WH_KEYBOARD_LL, callback, ...) call site.
_IME_SERVICE_CALLBACK_RVAS = {
    "8c51f6e78953598e75a89574ddb49a0fb78d3fa2bae8229290fcf1706274aedf": 0x726740,
    "86a863fd2b4be9526ab3cd88a857ba6354b8547e0b39319d950563cad3827435": 0x744520,
}
# Backward-compatible names retained for callers/tests that inspect the
# original verified build constants.
_IME_SERVICE_SHA256 = next(iter(_IME_SERVICE_CALLBACK_RVAS))
_IME_SERVICE_CALLBACK_RVA = _IME_SERVICE_CALLBACK_RVAS[_IME_SERVICE_SHA256]
# Must match legacy_key_suppressor_windows.VOICE_EVENT_EXTRA_INFO.  Keeping the
# literal here avoids importing the global-hook module into the elevated
# helper.  The Frida callback only clears flags on RemoteMic-owned events with
# this exact marker; unrelated synthetic Ctrl/Win input is left untouched.
_VOICE_EVENT_EXTRA_INFO = 0x524D494352433033


def _physicalizer_source(
    vk_codes: Tuple[int, ...],
    callback_rva: int = _IME_SERVICE_CALLBACK_RVA,
) -> str:
    """Return the Frida script that strips Doubao's injected-event marker.

    Doubao ignores Win32 synthetic key events (``LLKHF_INJECTED``).  The
    script hooks ImeService.exe's keyboard callback and clears that marker
    only for the configured voice hotkey's virtual keys, so the injected edge
    looks physical to Doubao.  The callback address, marker offset and module
    hash match one exact allow-listed DoubaoIME build (see
    ``_IME_SERVICE_CALLBACK_RVAS``).
    """

    codes_literal = ", ".join(f"0x{int(code):X}" for code in vk_codes)
    return f"""\
const module = Process.getModuleByName('ImeService.exe');
const callback = module.base.add(0x{int(callback_rva):X});
send({{type: 'ready', callback: callback.toString()}});
const targetVks = new Set([{codes_literal}]);
const remoteMicMarker = uint64('0x{_VOICE_EVENT_EXTRA_INFO:X}');
Interceptor.attach(callback, {{
  onEnter(args) {{
    if (args[0].toInt32() < 0) return;
    const event = args[2];
    const vk = event.readU32();
    const flags = event.add(8).readU32();
    const extraInfo = event.add(16).readU64();
    if (targetVks.has(vk) && (flags & 0x10) !== 0 &&
        extraInfo.compare(remoteMicMarker) === 0) {{
      event.add(8).writeU32(flags & ~0x12);
      event.add(16).writeU64(0);
    }}
  }}
}});
"""


class DoubaoRpcError(OSError):
    """Base class for failures talking to Doubao's native RPC client."""


class DoubaoRpcUnavailableError(DoubaoRpcError):
    """Doubao is not installed or its RPC exports are unavailable."""


class DoubaoRpcCallError(DoubaoRpcError):
    """The RPC call was made but Doubao rejected it."""


RpcFunction = Callable[..., int]


class DoubaoPhysicalizer:
    """Clear the injected marker only inside the verified Doubao callback."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._session = None
        self._script = None
        self._frida = None
        self._status = "not_started"
        self._error: Optional[str] = None

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def error(self) -> Optional[str]:
        with self._lock:
            return self._error

    def _set_failure(self, status: str, error: BaseException | str) -> bool:
        self._status = status
        self._error = str(error)
        return False

    @staticmethod
    def _module_probe_source() -> str:
        return (
            "const module = Process.getModuleByName('ImeService.exe');"
            "send({type: 'module', path: module.path, size: module.size});"
        )

    @staticmethod
    def _verified_callback_rva(path: str) -> Optional[int]:
        try:
            module_path = Path(path)
            if module_path.name.casefold() != _IME_SERVICE_NAME.casefold():
                return None
            if "doubaoime" not in str(module_path.parent).casefold():
                return None
            digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
        except OSError:
            return None
        return _IME_SERVICE_CALLBACK_RVAS.get(digest.casefold())

    @staticmethod
    def _verify_module(path: str) -> bool:
        """Compatibility predicate for exact, allow-listed Doubao builds."""

        return DoubaoPhysicalizer._verified_callback_rva(path) is not None

    def _probe_module(self, session: Any) -> Optional[str]:
        info: dict[str, Any] = {}
        ready = threading.Event()

        def on_message(message: dict[str, Any], _data: Any) -> None:
            if message.get("type") == "send":
                payload = message.get("payload") or {}
                if payload.get("type") == "module":
                    info.update(payload)
                    ready.set()
            elif message.get("type") == "error":
                ready.set()

        probe = session.create_script(self._module_probe_source())
        probe.on("message", on_message)
        try:
            probe.load()
            if not ready.wait(2.0):
                return None
            path = info.get("path")
            return str(path) if path else None
        finally:
            try:
                probe.unload()
            except Exception:
                pass

    def start(self, vk_codes: Tuple[int, ...] = (0xA5,)) -> bool:
        with self._lock:
            if self._script is not None and self._session is not None:
                return True
            self._status = "starting"
            self._error = None

            if sys.platform != "win32":
                return self._set_failure("unavailable", "Doubao physicalizer is Windows-only")
            try:
                import frida  # type: ignore[import-not-found]
            except ImportError as exc:
                return self._set_failure("unavailable", "Python frida package is not installed")

            try:
                device = frida.get_local_device()
                processes = device.enumerate_processes()
                candidates = [
                    process
                    for process in processes
                    if str(process.name).casefold() == _IME_SERVICE_NAME.casefold()
                ]
                if not candidates:
                    return self._set_failure("unavailable", "ImeService.exe is not running")
                last_error: Optional[BaseException] = None
                for process in candidates:
                    session = None
                    try:
                        session = frida.attach(process.pid)
                        module_path = self._probe_module(session)
                        callback_rva = (
                            self._verified_callback_rva(module_path)
                            if module_path
                            else None
                        )
                        if callback_rva is None:
                            raise RuntimeError(
                                "ImeService.exe path or SHA-256 does not match the verified build"
                            )
                        script = session.create_script(
                            _physicalizer_source(vk_codes, callback_rva)
                        )
                        script.load()
                        self._frida = frida
                        self._session = session
                        self._script = script
                        self._status = "active"
                        return True
                    except BaseException as exc:  # noqa: BLE001 - optional integration
                        last_error = exc
                        if session is not None:
                            try:
                                session.detach()
                            except Exception:
                                pass
                return self._set_failure("unavailable", last_error or "could not attach to ImeService.exe")
            except BaseException as exc:  # noqa: BLE001 - optional integration
                return self._set_failure("unavailable", exc)

    def stop(self) -> None:
        with self._lock:
            script, session = self._script, self._session
            self._script = None
            self._session = None
            self._frida = None
            self._status = "stopped"
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    pass
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass


_physicalizer = DoubaoPhysicalizer()


def start_physicalizer(vk_codes: Tuple[int, ...] = (0xA5,)) -> bool:
    """Install the verified in-process Doubao callback filter if possible."""

    return _physicalizer.start(vk_codes)


def stop_physicalizer() -> None:
    """Remove the optional Doubao callback filter."""

    _physicalizer.stop()


def physicalizer_status() -> str:
    return _physicalizer.status


def physicalizer_error() -> Optional[str]:
    return _physicalizer.error


def _candidate_dll_paths() -> Tuple[str, ...]:
    paths = []
    for variable in ("ProgramFiles", "ProgramW6432"):
        root = os.environ.get(variable)
        if root:
            paths.append(os.path.join(root, "DoubaoIME", _RPC_DLL_NAME))
    paths.append(os.path.join(r"C:\Program Files", "DoubaoIME", _RPC_DLL_NAME))
    return tuple(dict.fromkeys(paths))


def _configure_function(
    library: Any,
    name: str,
    argtypes: Tuple[Any, ...],
) -> RpcFunction:
    try:
        function = getattr(library, name)
    except AttributeError as exc:
        raise DoubaoRpcUnavailableError(f"Doubao rpc.dll is missing {name}") from exc
    function.argtypes = argtypes
    function.restype = ctypes.c_int32
    return function


@lru_cache(maxsize=1)
def _load_api() -> Tuple[RpcFunction, RpcFunction]:
    if sys.platform != "win32":
        raise DoubaoRpcUnavailableError("Doubao RPC is Windows-only")

    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise DoubaoRpcUnavailableError("ctypes.WinDLL is unavailable")

    dll_path = next((path for path in _candidate_dll_paths() if os.path.isfile(path)), None)
    if dll_path is None:
        raise DoubaoRpcUnavailableError("Doubao rpc.dll was not found")
    try:
        library = loader(dll_path)
    except OSError as exc:
        raise DoubaoRpcUnavailableError(f"could not load Doubao rpc.dll: {exc}") from exc

    key_down = _configure_function(
        library,
        "RpcPipe_KeyDown",
        (ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_char_p),
    )
    key_up = _configure_function(
        library,
        "RpcPipe_KeyUp",
        (ctypes.c_char_p, ctypes.c_uint32),
    )
    return key_down, key_up


def clear_cached_api() -> None:
    """Clear the lazy DLL handle, primarily for tests and app restarts."""

    _load_api.cache_clear()


def send_key_edge(
    vk_code: int,
    key_up: bool,
    *,
    endpoint: str = DEFAULT_PIPE,
    event_value: int = 0,
    context: Optional[bytes] = None,
) -> None:
    """Send one virtual-key edge through Doubao's own RPC input path.

    ``RpcPipe_KeyDown`` and ``RpcPipe_KeyUp`` return zero on the successful
    path.  A nonzero result is treated as a hard failure so callers do not
    silently mix a partially delivered RPC hold with a Win32 fallback.
    """

    key_down, key_up_function = _load_api()
    endpoint_bytes = endpoint.encode("ascii")
    try:
        if key_up:
            result = key_up_function(endpoint_bytes, int(vk_code))
        else:
            result = key_down(
                endpoint_bytes,
                int(vk_code),
                int(event_value),
                context,
            )
    except (OSError, ValueError) as exc:
        raise DoubaoRpcCallError(f"Doubao RPC key edge failed: {exc}") from exc

    if int(result) != 0:
        operation = "up" if key_up else "down"
        raise DoubaoRpcCallError(
            f"Doubao RPC key-{operation} returned nonzero status {int(result)}"
        )
