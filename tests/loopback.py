"""Run the REAL HTTP servers in tests even where TCP sockets are not allowed.

The release builder's offline test phase has RestrictAddressFamilies=AF_UNIX (and no network at all), so a test that starts the
owner service's loopback listeners cannot create an AF_INET socket there. Instead of skipping those tests, this swaps ONLY the
transport: the same uvicorn server, the same app, the same validation in run.start / start_approval and the same HTTP requests,
over a private AF_UNIX socket. Wherever TCP works (developer machines, reviews) nothing is swapped and real 127.0.0.1 is used.
The few tests whose subject is the TCP connection itself use ``needs_tcp``.
"""
import itertools
import os
import socket
import tempfile
import unittest

import httpx


def _tcp_available():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


TCP = _tcp_available()
REASON = "this environment allows no TCP sockets (release sandbox: RestrictAddressFamilies=AF_UNIX); this test's subject is TCP itself"
needs_tcp = unittest.skipUnless(TCP, REASON)
_ports = itertools.count(40000)
_dir = None


def free_port():
    if TCP:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
    return next(_ports)


def _socket_for(port):
    global _dir
    if _dir is None:
        _dir = tempfile.mkdtemp(prefix="styn-uds-")
    return os.path.join(_dir, "%d.sock" % port)


def install(testcase):
    """In an AF_UNIX-only environment, make uvicorn serve each requested 127.0.0.1:<port> on its own unix socket."""
    if TCP:
        return
    import uvicorn
    real = uvicorn.Config.__init__

    def config(self, app, *args, host="127.0.0.1", port=8000, uds=None, **kw):
        if host != "127.0.0.1" or uds is not None:
            raise AssertionError("tests only ever serve on 127.0.0.1")
        real(self, app, *args, uds=_socket_for(port), **kw)

    uvicorn.Config.__init__ = config
    testcase.addCleanup(setattr, uvicorn.Config, "__init__", real)


def client(base_url, **kw):
    """An httpx client for http://127.0.0.1:<port>: over TCP where it exists, otherwise over that port's unix socket."""
    if not TCP:
        port = int(base_url.rsplit(":", 1)[1].split("/")[0])
        kw["transport"] = httpx.HTTPTransport(uds=_socket_for(port))
    return httpx.Client(base_url=base_url, **kw)


def post(url, **kw):
    if TCP:
        return httpx.post(url, **kw)
    base = url.split("/", 3)
    with client("/".join(base[:3]), trust_env=kw.pop("trust_env", False)) as c:
        return c.post("/" + (base[3] if len(base) > 3 else ""), **kw)
