"""Sanitized Phase 12 API failures and FastAPI handlers."""

from __future__ import annotations

import logging
from typing import NoReturn, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.api.contracts import ErrorResponse
from aegishunt.cases.errors import CaseConflictError, CaseTransitionError
from aegishunt.correlation.errors import CorrelationPersistenceError
from aegishunt.detection.errors import DetectionPersistenceError
from aegishunt.errors import (
    AegisHuntError,
    RepositoryIntegrityError,
    RepositoryRecordNotFoundError,
)
from aegishunt.feedback.errors import FeedbackConflictError
from aegishunt.hunting.errors import HypothesisTransitionError
from aegishunt.runtime.errors import RuntimeStateError
from aegishunt.schemas.base import JsonObject

logger = logging.getLogger(__name__)


class ApiError(AegisHuntError):
    """A controlled public failure with no sensitive implementation details."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status_code: int,
        retryable: bool = False,
        details: JsonObject | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.retryable = retryable
        self.details = details


def not_found(resource: str) -> NoReturn:
    """Raise a uniform resource-not-found response."""

    raise ApiError(
        f"{resource} does not exist",
        code="resource_not_found",
        status_code=404,
    )


def conflict(message: str) -> NoReturn:
    """Raise a uniform optimistic/state conflict response."""

    raise ApiError(message, code="state_conflict", status_code=409)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))


def _payload(
    request: Request,
    *,
    code: str,
    message: str,
    status_code: int,
    retryable: bool = False,
    details: JsonObject | None = None,
) -> dict[str, object]:
    return ErrorResponse(
        error_code=code,
        message=message,
        request_id=_request_id(request),
        details=details,
        retryable=retryable,
        status_code=status_code,
    ).model_dump(mode="json")


def install_error_handlers(application: FastAPI) -> None:
    """Install stable handlers without returning tracebacks or local paths."""

    @application.exception_handler(ApiError)
    async def api_error(request: Request, error: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(
                request,
                code=error.code,
                message=str(error),
                status_code=error.status_code,
                retryable=error.retryable,
                details=error.details,
            ),
        )

    @application.exception_handler(RepositoryRecordNotFoundError)
    async def repository_not_found(
        request: Request, error: RepositoryRecordNotFoundError
    ) -> JSONResponse:
        del error
        return JSONResponse(
            status_code=404,
            content=_payload(
                request,
                code="resource_not_found",
                message="requested resource does not exist",
                status_code=404,
            ),
        )

    @application.exception_handler(RepositoryIntegrityError)
    @application.exception_handler(CaseConflictError)
    @application.exception_handler(CaseTransitionError)
    @application.exception_handler(FeedbackConflictError)
    @application.exception_handler(HypothesisTransitionError)
    @application.exception_handler(RuntimeStateError)
    @application.exception_handler(DetectionPersistenceError)
    @application.exception_handler(CorrelationPersistenceError)
    async def state_conflict(request: Request, error: AegisHuntError) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content=_payload(
                request,
                code="state_conflict",
                message=str(error),
                status_code=409,
            ),
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        details = {
            "errors": [
                {
                    "location": ".".join(str(item) for item in issue["loc"]),
                    "type": issue["type"],
                    "message": issue["msg"],
                }
                for issue in error.errors()
            ]
        }
        return JSONResponse(
            status_code=422,
            content=_payload(
                request,
                code="request_validation_failed",
                message="request validation failed",
                status_code=422,
                details=cast(JsonObject, details),
            ),
        )

    @application.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        message = "request could not be completed"
        code = "http_error"
        details: JsonObject | None = None
        if isinstance(error.detail, dict):
            message = str(error.detail.get("message", message))
            code = str(error.detail.get("code", code))
            extra = {
                str(key): value
                for key, value in error.detail.items()
                if key not in {"message", "code"}
            }
            details = cast(JsonObject, extra) if extra else None
        elif isinstance(error.detail, str):
            message = error.detail
        return JSONResponse(
            status_code=error.status_code,
            content=_payload(
                request,
                code=code,
                message=message,
                status_code=error.status_code,
                details=details,
            ),
        )

    @application.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, error: SQLAlchemyError) -> JSONResponse:
        del error
        logger.error("database request failed; details withheld")
        return JSONResponse(
            status_code=503,
            content=_payload(
                request,
                code="database_unavailable",
                message="database is unavailable; request was not completed",
                status_code=503,
                retryable=True,
            ),
        )

    @application.exception_handler(AegisHuntError)
    async def domain_error(request: Request, error: AegisHuntError) -> JSONResponse:
        logger.warning("domain request was rejected: %s", type(error).__name__)
        return JSONResponse(
            status_code=422,
            content=_payload(
                request,
                code=getattr(error, "code", "domain_request_rejected"),
                message=str(error),
                status_code=422,
            ),
        )

    @application.exception_handler(Exception)
    async def internal_error(request: Request, error: Exception) -> JSONResponse:
        logger.exception("unexpected API failure", exc_info=error)
        return JSONResponse(
            status_code=500,
            content=_payload(
                request,
                code="internal_error",
                message="request failed unexpectedly",
                status_code=500,
            ),
        )
