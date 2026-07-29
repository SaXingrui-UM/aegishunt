"""Request identity and response-safety middleware."""

from __future__ import annotations

import re
from collections.abc import Mapping
from uuid import uuid4

from fastapi import FastAPI, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]+$")


class _RequestBodyLimitExceeded(Exception):
    """Internal control signal raised before multipart parsing can continue."""


class RequestBodyLimitMiddleware:
    """Bound raw request bodies before FastAPI/Starlette multipart spooling."""

    def __init__(self, app: ASGIApp, *, limits: Mapping[str, int]) -> None:
        self._app = app
        self._limits = dict(limits)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "detail": {
                    "code": "request_body_too_large",
                    "message": "request body exceeds the configured endpoint limit",
                }
            },
        )
        await response(scope, receive, send)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self._app(scope, receive, send)
            return
        limit = self._limits.get(str(scope.get("path", "")))
        if limit is None:
            await self._app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", ())}
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            try:
                if int(declared_length) > limit:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                pass

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _RequestBodyLimitExceeded
            return message

        try:
            await self._app(scope, limited_receive, send)
        except _RequestBodyLimitExceeded:
            await self._reject(scope, receive, send)


def install_request_body_limit_middleware(
    application: FastAPI,
    *,
    endpoint_limits: Mapping[str, int],
) -> None:
    """Install endpoint-specific raw-body bounds before multipart materialization."""

    application.add_middleware(
        RequestBodyLimitMiddleware,
        limits=dict(endpoint_limits),
    )


def install_request_id_middleware(
    application: FastAPI,
    *,
    header_name: str,
    maximum_length: int,
) -> None:
    """Accept one bounded safe request ID or generate a random identity."""

    @application.middleware("http")
    async def request_identity(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        candidate = request.headers.get(header_name, "")
        request_id = (
            candidate
            if 1 <= len(candidate) <= maximum_length and _REQUEST_ID.fullmatch(candidate)
            else uuid4().hex
        )
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[header_name] = request_id
        return response
