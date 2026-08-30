"""Error responses an agent can act on.

buenavista's `send_error` writes only the message field, so every failure
reaches the client as an untyped string. An agent then cannot tell "policy
refused this" from "this SQL is invalid" without matching on message text.
This module sends a real ErrorResponse -- severity, SQLSTATE, message and
detail -- so a refusal is machine-distinguishable.
"""

from __future__ import annotations

import socketserver
import struct
from typing import Any

from buenavista.postgres import NULL_BYTE, BuenaVistaHandler, BuenaVistaServer, ServerResponse

from dblocker.core.decision import SQLSTATE_INSUFFICIENT_PRIVILEGE

# internal_error: dblocker could not establish what a statement would do.
SQLSTATE_INTERNAL_ERROR = "XX000"
# io_error: provenance could not be written, so the query was refused. Distinct
# from insufficient_privilege because this one is worth retrying unchanged.
SQLSTATE_LEDGER_UNAVAILABLE = "58030"


class PolicyViolation(Exception):
    """Raised to refuse a query. Carries a SQLSTATE and an optional detail."""

    def __init__(
        self,
        message: str,
        *,
        sqlstate: str = SQLSTATE_INSUFFICIENT_PRIVILEGE,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate
        self.detail = detail


class DblockerHandler(BuenaVistaHandler):
    """buenavista's handler with a standards-shaped error response."""

    def send_error(self, exception: Any, ctx: Any = None) -> None:
        message = str(exception)
        sqlstate = getattr(exception, "sqlstate", None) or SQLSTATE_INTERNAL_ERROR
        detail = getattr(exception, "detail", None)

        fields: list[tuple[bytes, str]] = [
            (b"S", "ERROR"),
            (b"V", "ERROR"),
            (b"C", sqlstate),
            (b"M", message),
        ]
        if detail:
            fields.append((b"D", detail))

        body = bytearray()
        for code, value in fields:
            body += code + value.encode("utf-8") + NULL_BYTE
        body += NULL_BYTE  # terminator for the field list

        self.wfile.write(
            struct.pack("!ci", ServerResponse.ERROR_RESPONSE, len(body) + 4) + bytes(body)
        )
        if ctx:
            ctx.mark_error()


class DblockerServer(BuenaVistaServer):
    """BuenaVistaServer bound to `DblockerHandler` and the configured address.

    `BuenaVistaServer.__init__` hardcodes both its handler class and a
    loopback-only `verify_request`, so neither can be set by configuration.
    This subclass reimplements that constructor to install the handler above,
    and honours the address dblocker was actually told to bind.
    """

    def __init__(
        self,
        server_address: tuple[str, int],
        conn: Any,
        *,
        rewriter: Any = None,
        extensions: list[Any] | None = None,
        auth: dict[str, str] | None = None,
    ) -> None:
        # Deliberately skips BuenaVistaServer.__init__ so a different handler
        # class can be installed; the attributes it sets are set here instead.
        socketserver.ThreadingTCPServer.__init__(self, server_address, DblockerHandler)
        self.conn = conn
        self.rewriter = rewriter
        self.extensions = {e.type(): e for e in (extensions or [])}
        self.ctxts: dict[int, Any] = {}
        self.auth = auth

    def verify_request(self, request: Any, client_address: Any) -> bool:
        """Accept any peer, because the bind address already decides reach.

        The base class hardcodes a 127.0.0.1 check that silently drops remote
        clients even when configured to listen on another interface. dblocker
        instead refuses at startup to bind a non-loopback address without
        authentication (see `Config.__post_init__`), so a remote peer that
        reaches this point still has to authenticate.
        """
        return True
