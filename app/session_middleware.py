"""
Cookie-based signed session middleware using only Python stdlib.
Drops in as a replacement for starlette.middleware.sessions.SessionMiddleware —
sets scope["session"] so request.session works identically in FastAPI/Starlette.
"""
import base64
import hashlib
import hmac
import json

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send


class SessionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        secret_key: str,
        session_cookie: str = "session",
        https_only: bool = False,
    ):
        self.app = app
        self.secret = secret_key.encode()
        self.session_cookie = session_cookie
        self.https_only = https_only

    def _sign(self, payload: bytes) -> str:
        b64 = base64.urlsafe_b64encode(payload).decode()
        sig = hmac.new(self.secret, b64.encode(), hashlib.sha256).hexdigest()
        return f"{b64}.{sig}"

    def _unsign(self, value: str) -> bytes | None:
        try:
            b64, sig = value.rsplit(".", 1)
            expected = hmac.new(self.secret, b64.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig, expected):
                return base64.urlsafe_b64decode(b64)
        except Exception:
            pass
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_empty = True

        cookie_val = connection.cookies.get(self.session_cookie, "")
        if cookie_val:
            raw = self._unsign(cookie_val)
            if raw:
                try:
                    scope["session"] = json.loads(raw.decode())
                    initial_empty = False
                except Exception:
                    scope["session"] = {}
            else:
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if scope["session"]:
                    payload = json.dumps(scope["session"]).encode()
                    cookie_value = self._sign(payload)
                    flags = "Path=/; HttpOnly; SameSite=lax"
                    if self.https_only:
                        flags += "; Secure"
                    headers.append("Set-Cookie", f"{self.session_cookie}={cookie_value}; {flags}")
                elif not initial_empty:
                    headers.append(
                        "Set-Cookie",
                        f"{self.session_cookie}=; Path=/; Max-Age=0; HttpOnly",
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)
