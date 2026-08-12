"""Narrow UAC helper for Doubao's SYSTEM-owned keyboard callback.

The ordinary RC003 bridge deliberately stays at the user's normal integrity
level.  Current Doubao builds run ``ImeService.exe`` above that level, so
Frida cannot enumerate or attach to it from the bridge process.  This module
starts the *same verified physicalizer* in a small elevated child instead of
elevating the BLE, audio, Raw Input, or global legacy-key hook code.

The helper has three important safety boundaries:

* it accepts only a short list of virtual-key codes and delegates the actual
  attach to :mod:`doubao_rpc`, whose executable hash/RVA allow-list fails
  closed after every unknown Doubao update;
* it verifies that the parent PID belongs to the exact same executable as the
  helper, then waits on that process handle and exits as soon as the bridge
  exits;
* readiness is reported through random, per-launch named events.  No elevated
  process writes a caller-selected file and no keyboard event is synthesized
  by this module.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import threading
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Sequence, Tuple


HELPER_FLAG = "--doubao-physicalizer-helper"

_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_EVENT_MODIFY_STATE = 0x0002
_SYNCHRONIZE = 0x00100000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF
_ERROR_CANCELLED = 1223
_HELPER_START_TIMEOUT_SECONDS = 10.0
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


class DoubaoElevationError(OSError):
    """The elevated helper could not be launched or verified."""


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HANDLE),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


_state_lock = threading.RLock()
_helper_process_handle: Optional[int] = None
_helper_vk_codes: Optional[Tuple[int, ...]] = None
_last_error: Optional[str] = None


def _require_windows() -> None:
    if sys.platform != "win32":
        raise DoubaoElevationError("the Doubao elevation helper is Windows-only")


def _normalize_vk_codes(vk_codes: Sequence[int]) -> Tuple[int, ...]:
    normalized = tuple(dict.fromkeys(int(code) for code in vk_codes))
    if not normalized or len(normalized) > 8:
        raise ValueError("the helper requires between one and eight virtual keys")
    if any(code <= 0 or code > 0xFF for code in normalized):
        raise ValueError("virtual-key codes must be in the range 0x01..0xFF")
    return normalized


def _encode_vk_codes(vk_codes: Sequence[int]) -> str:
    return ",".join(f"{code:02X}" for code in _normalize_vk_codes(vk_codes))


def _decode_vk_codes(value: str) -> Tuple[int, ...]:
    parts = value.split(",") if value else []
    if not parts or any(not re.fullmatch(r"[0-9A-Fa-f]{2}", part) for part in parts):
        raise ValueError("invalid virtual-key list")
    return _normalize_vk_codes(tuple(int(part, 16) for part in parts))


def _event_names(parent_pid: int, nonce: str) -> Tuple[str, str]:
    if int(parent_pid) <= 0:
        raise ValueError("parent PID must be positive")
    normalized_nonce = str(nonce).casefold()
    if not _NONCE_RE.fullmatch(normalized_nonce):
        raise ValueError("invalid helper nonce")
    stem = f"Local\\RemoteMicRC003_Doubao_{int(parent_pid)}_{normalized_nonce}"
    return f"{stem}_ready", f"{stem}_failed"


def build_helper_command(
    executable: str,
    *,
    frozen: bool,
    parent_pid: int,
    nonce: str,
    vk_codes: Sequence[int],
) -> list[str]:
    """Build the hidden helper command for source and frozen runtimes."""

    _event_names(parent_pid, nonce)
    suffix = [
        HELPER_FLAG,
        str(int(parent_pid)),
        str(nonce).casefold(),
        _encode_vk_codes(vk_codes),
    ]
    if frozen:
        return [str(executable), *suffix]
    return [str(executable), "-m", "ovb_rc003", *suffix]


def parse_helper_args(args: Sequence[str]) -> Tuple[int, str, Tuple[int, ...]]:
    """Parse only the three positional arguments following ``HELPER_FLAG``."""

    if len(args) != 3:
        raise ValueError("the helper requires parent PID, nonce, and virtual keys")
    try:
        parent_pid = int(args[0], 10)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid parent PID") from exc
    nonce = str(args[1]).casefold()
    _event_names(parent_pid, nonce)
    return parent_pid, nonce, _decode_vk_codes(str(args[2]))


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _close_handle(handle: Optional[int]) -> None:
    if not handle:
        return
    kernel32 = _kernel32()
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(wintypes.HANDLE(handle))


def _wait_for_single_object(handle: int, timeout_ms: int) -> int:
    kernel32 = _kernel32()
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    return int(kernel32.WaitForSingleObject(wintypes.HANDLE(handle), timeout_ms))


def _helper_is_alive(handle: Optional[int]) -> bool:
    return bool(handle) and _wait_for_single_object(int(handle), 0) == _WAIT_TIMEOUT


def _create_event(name: str) -> int:
    kernel32 = _kernel32()
    kernel32.CreateEventW.argtypes = (
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    )
    kernel32.CreateEventW.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    handle = kernel32.CreateEventW(None, True, False, name)
    if not handle:
        raise DoubaoElevationError(
            f"CreateEventW failed (GetLastError={ctypes.get_last_error()})"
        )
    return int(handle)


def _open_event(name: str) -> int:
    kernel32 = _kernel32()
    kernel32.OpenEventW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.OpenEventW.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    handle = kernel32.OpenEventW(_EVENT_MODIFY_STATE, False, name)
    if not handle:
        raise DoubaoElevationError(
            f"OpenEventW failed (GetLastError={ctypes.get_last_error()})"
        )
    return int(handle)


def _set_event(handle: int) -> None:
    kernel32 = _kernel32()
    kernel32.SetEvent.argtypes = (wintypes.HANDLE,)
    kernel32.SetEvent.restype = wintypes.BOOL
    if not kernel32.SetEvent(wintypes.HANDLE(handle)):
        raise DoubaoElevationError(
            f"SetEvent failed (GetLastError={ctypes.get_last_error()})"
        )


def _wait_for_launch_result(
    ready_handle: int,
    failed_handle: int,
    process_handle: int,
    timeout_seconds: float,
) -> str:
    kernel32 = _kernel32()
    handles = (wintypes.HANDLE * 3)(
        wintypes.HANDLE(ready_handle),
        wintypes.HANDLE(failed_handle),
        wintypes.HANDLE(process_handle),
    )
    kernel32.WaitForMultipleObjects.argtypes = (
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
    timeout_ms = max(0, min(int(float(timeout_seconds) * 1000), 0xFFFFFFFE))
    result = int(kernel32.WaitForMultipleObjects(3, handles, False, timeout_ms))
    if result == _WAIT_OBJECT_0:
        return "ready"
    if result == _WAIT_OBJECT_0 + 1:
        return "failed"
    if result == _WAIT_OBJECT_0 + 2:
        return "exited"
    if result == _WAIT_TIMEOUT:
        return "timeout"
    if result == _WAIT_FAILED:
        raise DoubaoElevationError(
            f"WaitForMultipleObjects failed (GetLastError={ctypes.get_last_error()})"
        )
    raise DoubaoElevationError(f"unexpected helper wait result {result}")


def _shell_execute_elevated(command: Sequence[str]) -> Tuple[int, int]:
    _require_windows()
    if not command:
        raise DoubaoElevationError("empty helper command")
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = (ctypes.POINTER(_SHELLEXECUTEINFOW),)
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = str(command[0])
    info.lpParameters = subprocess.list2cmdline(list(command[1:]))
    info.lpDirectory = str(Path(command[0]).resolve().parent)
    info.nShow = _SW_HIDE
    ctypes.set_last_error(0)
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == _ERROR_CANCELLED:
            raise DoubaoElevationError("administrator approval was cancelled")
        raise DoubaoElevationError(
            f"ShellExecuteExW failed (GetLastError={error})"
        )
    if not info.hProcess:
        raise DoubaoElevationError("ShellExecuteExW returned no process handle")
    process_handle = int(info.hProcess)
    kernel32 = _kernel32()
    kernel32.GetProcessId.argtypes = (wintypes.HANDLE,)
    kernel32.GetProcessId.restype = wintypes.DWORD
    process_id = int(kernel32.GetProcessId(wintypes.HANDLE(process_handle)))
    if not process_id:
        _close_handle(process_handle)
        raise DoubaoElevationError("GetProcessId returned zero for the helper")
    return process_handle, process_id


def ensure_elevated_physicalizer(
    vk_codes: Sequence[int],
    *,
    timeout_seconds: float = 15.0,
) -> bool:
    """Ensure one elevated helper is active for this bridge process.

    This is the only function that can display UAC.  It never synthesizes a
    key and returns only after the helper reports that the exact allow-listed
    Doubao callback was attached.
    """

    global _helper_process_handle, _helper_vk_codes, _last_error
    normalized_codes = _normalize_vk_codes(vk_codes)
    with _state_lock:
        if _helper_is_alive(_helper_process_handle):
            if _helper_vk_codes == normalized_codes:
                _last_error = None
                return True
            _last_error = "voice hotkey changed; restart RemoteMic before relaunching helper"
            return False
        if _helper_process_handle:
            _close_handle(_helper_process_handle)
            _helper_process_handle = None
            _helper_vk_codes = None

        parent_pid = os.getpid()
        nonce = uuid.uuid4().hex
        ready_name, failed_name = _event_names(parent_pid, nonce)
        ready_handle = failed_handle = process_handle = None
        try:
            ready_handle = _create_event(ready_name)
            failed_handle = _create_event(failed_name)
            command = build_helper_command(
                sys.executable,
                frozen=bool(getattr(sys, "frozen", False)),
                parent_pid=parent_pid,
                nonce=nonce,
                vk_codes=normalized_codes,
            )
            process_handle, _process_id = _shell_execute_elevated(command)
            outcome = _wait_for_launch_result(
                ready_handle, failed_handle, process_handle, timeout_seconds
            )
            if outcome != "ready":
                _last_error = {
                    "failed": "the elevated helper rejected the Doubao attach",
                    "exited": "the elevated helper exited before becoming ready",
                    "timeout": "the elevated helper did not become ready in time",
                }[outcome]
                _close_handle(process_handle)
                process_handle = None
                return False
            _helper_process_handle = process_handle
            _helper_vk_codes = normalized_codes
            _last_error = None
            process_handle = None  # ownership moved to module state
            return True
        except (DoubaoElevationError, OSError, ValueError) as exc:
            _last_error = str(exc)
            return False
        finally:
            _close_handle(ready_handle)
            _close_handle(failed_handle)
            _close_handle(process_handle)


def elevation_error() -> Optional[str]:
    with _state_lock:
        return _last_error


def _open_and_verify_parent(parent_pid: int) -> int:
    kernel32 = _kernel32()
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    access = _SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION
    ctypes.set_last_error(0)
    handle = kernel32.OpenProcess(access, False, int(parent_pid))
    if not handle:
        raise DoubaoElevationError(
            f"OpenProcess(parent) failed (GetLastError={ctypes.get_last_error()})"
        )
    parent_handle = int(handle)
    try:
        kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(
            wintypes.HANDLE(parent_handle), 0, buffer, ctypes.byref(size)
        ):
            raise DoubaoElevationError(
                "QueryFullProcessImageNameW(parent) failed "
                f"(GetLastError={ctypes.get_last_error()})"
            )
        parent_image = Path(buffer.value).resolve()
        helper_image = Path(sys.executable).resolve()
        if os.path.normcase(str(parent_image)) != os.path.normcase(str(helper_image)):
            raise DoubaoElevationError("helper parent executable does not match")
        return parent_handle
    except BaseException:
        _close_handle(parent_handle)
        raise


def helper_main(args: Sequence[str]) -> int:
    """Hidden elevated child entry point; never starts BLE or keyboard input."""

    ready_handle = failed_handle = parent_handle = None
    physicalizer_started = False
    try:
        _require_windows()
        parent_pid, nonce, vk_codes = parse_helper_args(args)
        ready_name, failed_name = _event_names(parent_pid, nonce)
        ready_handle = _open_event(ready_name)
        failed_handle = _open_event(failed_name)
        parent_handle = _open_and_verify_parent(parent_pid)

        # A native attach should finish quickly.  Bound the elevated helper's
        # startup even if a future Frida build blocks unexpectedly; a daemon
        # thread cannot keep this small helper process alive after failure.
        result: list[bool] = []

        def start_verified_physicalizer() -> None:
            from . import doubao_rpc

            result.append(bool(doubao_rpc.start_physicalizer(tuple(vk_codes))))

        worker = threading.Thread(target=start_verified_physicalizer, daemon=True)
        worker.start()
        worker.join(_HELPER_START_TIMEOUT_SECONDS)
        if worker.is_alive() or not result or not result[0]:
            _set_event(failed_handle)
            return 2
        physicalizer_started = True
        _set_event(ready_handle)
        _wait_for_single_object(parent_handle, _INFINITE)
        return 0
    except (DoubaoElevationError, OSError, ValueError):
        if failed_handle:
            try:
                _set_event(failed_handle)
            except Exception:
                pass
        return 2
    finally:
        if physicalizer_started:
            try:
                from . import doubao_rpc

                doubao_rpc.stop_physicalizer()
            except Exception:
                pass
        _close_handle(parent_handle)
        _close_handle(ready_handle)
        _close_handle(failed_handle)


def _reset_state_for_tests() -> None:
    global _helper_process_handle, _helper_vk_codes, _last_error
    with _state_lock:
        _close_handle(_helper_process_handle)
        _helper_process_handle = None
        _helper_vk_codes = None
        _last_error = None
