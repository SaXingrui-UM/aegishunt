"""Request identity and response-safety middleware."""

from __future__ import annotations

import re
from uuid import uuid4

from fastapi import FastAPI, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]+$")


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
