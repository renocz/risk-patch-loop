"""Test package. Importing it installs a guard: the tests may talk to 127.0.0.1 (the fake registry) and nothing else.
A test that tries to resolve or connect to any other host fails instead of reaching the network."""
import socket

_LOOPBACK = ("127.0.0.1", "::1", "localhost")
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect


def _getaddrinfo(host, *args, **kw):
    if host not in _LOOPBACK:
        raise AssertionError(f"tests must not use the network (name lookup of {host!r})")
    return _real_getaddrinfo(host, *args, **kw)


def _connect(self, address):
    if isinstance(address, tuple) and address[0] not in _LOOPBACK:
        raise AssertionError(f"tests must not use the network (connect to {address[0]!r})")
    return _real_connect(self, address)


socket.getaddrinfo = _getaddrinfo
socket.socket.connect = _connect
