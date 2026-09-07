from typing import Literal

from fastapi import APIRouter, Request

from xcheck.services.dashboard import build_dashboard

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def get_dashboard(
    request: Request,
    mode: Literal["overview", "landscape", "operations"] | None = None,
):
    selected_mode = mode or request.app.state.settings.homepage_mode
    with request.app.state.session_factory() as session:
        return build_dashboard(
            session,
            request.app.state.settings,
            selected_mode,
            worker_ready=hasattr(request.app.state, "worker"),
            database_ready=True,
        )
