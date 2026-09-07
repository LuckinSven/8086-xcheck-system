from typing import NoReturn

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ApiProblem(BaseModel):
    code: str
    fallback: str
    params: dict[str, str | int] = Field(default_factory=dict)


def raise_api_problem(
    status_code: int,
    code: str,
    fallback: str,
    **params: str | int,
) -> NoReturn:
    problem = ApiProblem(code=code, fallback=fallback, params=params)
    raise HTTPException(status_code=status_code, detail=problem.model_dump())


async def validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    first_error = exc.errors()[0] if exc.errors() else {}
    location = first_error.get("loc", ())
    field = str(location[-1]) if location else "request"
    problem = ApiProblem(
        code="request.validation_failed",
        fallback="The request contains invalid values.",
        params={"field": field},
    )
    return JSONResponse(status_code=422, content={"detail": problem.model_dump()})
