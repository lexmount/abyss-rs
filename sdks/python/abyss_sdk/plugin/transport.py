"""Platform-local stream connection used by the plugin runtime."""

import json
import os
import socket
from pathlib import Path
from typing import Optional, Protocol

from .errors import AbyssPluginError


class PluginTransport(Protocol):
    """Minimal byte-stream operations required by plugin framing."""

    def read(self, size: int) -> bytes: ...

    def write_all(self, data: bytes) -> None: ...

    def close(self) -> None: ...


class SocketTransport:
    """Unix domain socket transport."""

    def __init__(self, stream: socket.socket) -> None:
        self._stream = stream

    def read(self, size: int) -> bytes:
        return self._stream.recv(size)

    def write_all(self, data: bytes) -> None:
        self._stream.sendall(data)

    def close(self) -> None:
        self._stream.close()


def resolve_plugin_endpoint(explicit: Optional[str] = None) -> str:
    """Resolve a concrete endpoint using the published discovery precedence."""

    if explicit is not None and explicit.strip():
        return explicit
    environment_endpoint = os.environ.get("ABYSS_BROKER_PLUGIN_ENDPOINT", "").strip()
    if environment_endpoint:
        return environment_endpoint
    startup_info = os.environ.get("ABYSS_BROKER_STARTUP_INFO", "").strip()
    if not startup_info:
        abyss_home = os.environ.get("ABYSS_HOME", "").strip()
        if abyss_home:
            startup_info = str(Path(abyss_home) / "runtime" / "startup-info.json")
    if not startup_info:
        raise AbyssPluginError(
            "broker plugin endpoint is unavailable; configure "
            "ABYSS_BROKER_PLUGIN_ENDPOINT, ABYSS_BROKER_STARTUP_INFO, or ABYSS_HOME"
        )
    try:
        parsed = json.loads(Path(startup_info).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AbyssPluginError(f"read broker startup info {startup_info}") from error
    endpoint = parsed.get("plugin_endpoint") if isinstance(parsed, dict) else None
    if not isinstance(endpoint, str) or not endpoint:
        raise AbyssPluginError("broker startup info has no plugin_endpoint")
    return endpoint


def connect_plugin_transport(endpoint: str) -> PluginTransport:
    """Connect a Unix domain socket or Windows Named Pipe byte stream."""

    try:
        if os.name == "nt":
            return _WindowsNamedPipeTransport.connect(endpoint)
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.connect(endpoint)
        return SocketTransport(stream)
    except OSError as error:
        raise AbyssPluginError(f"connect to broker plugin endpoint {endpoint}") from error


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _ERROR_PIPE_BUSY = 231
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _PIPE_WAIT_MS = 10_000
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL

    class _WindowsNamedPipeTransport:
        """Raw byte-stream wrapper around a broker-owned Windows Named Pipe."""

        def __init__(self, handle: int) -> None:
            self._handle = handle

        @classmethod
        def connect(cls, endpoint: str) -> "_WindowsNamedPipeTransport":
            while True:
                handle = _kernel32.CreateFileW(
                    endpoint,
                    _GENERIC_READ | _GENERIC_WRITE,
                    0,
                    None,
                    _OPEN_EXISTING,
                    0,
                    None,
                )
                if handle != _INVALID_HANDLE_VALUE:
                    return cls(handle)
                error = ctypes.get_last_error()
                if error != _ERROR_PIPE_BUSY or not _kernel32.WaitNamedPipeW(
                    endpoint, _PIPE_WAIT_MS
                ):
                    raise ctypes.WinError(error)

        def read(self, size: int) -> bytes:
            buffer = ctypes.create_string_buffer(size)
            read = wintypes.DWORD()
            if not _kernel32.ReadFile(self._handle, buffer, size, ctypes.byref(read), None):
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer.raw[: read.value]

        def write_all(self, data: bytes) -> None:
            offset = 0
            while offset < len(data):
                written = wintypes.DWORD()
                chunk = data[offset:]
                buffer = ctypes.create_string_buffer(chunk)
                if not _kernel32.WriteFile(
                    self._handle, buffer, len(chunk), ctypes.byref(written), None
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                if written.value == 0:
                    raise OSError("Windows Named Pipe write made no progress")
                offset += written.value

        def close(self) -> None:
            if self._handle != _INVALID_HANDLE_VALUE:
                _kernel32.CloseHandle(self._handle)
                self._handle = _INVALID_HANDLE_VALUE

else:

    class _WindowsNamedPipeTransport:
        @classmethod
        def connect(cls, endpoint: str) -> PluginTransport:
            del endpoint
            raise OSError("Windows Named Pipes are unavailable on this platform")
