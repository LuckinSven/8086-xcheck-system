from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from xcheck.models import Task
from xcheck.services.exports import STAGE_FILTERS, txt_stream, xlsx_bytes

router = APIRouter(prefix="/api/tasks", tags=["exports"])


@router.get("/{task_id}/exports/{stage}.{format_name}")
def export_stage(task_id: str, stage: str, format_name: str, request: Request):
    if stage not in STAGE_FILTERS or format_name not in {"txt", "xlsx"}:
        raise HTTPException(404, "导出类型不存在")
    session = request.app.state.session_factory()
    if session.get(Task, task_id) is None:
        session.close()
        raise HTTPException(404, "任务不存在")
    filename = f"xcheck-{task_id}-{stage}.{format_name}"
    if format_name == "txt":

        def generate():
            try:
                yield from txt_stream(session, task_id, stage)
            finally:
                session.close()

        return StreamingResponse(
            generate(),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    try:
        content = xlsx_bytes(session, task_id, stage)
    finally:
        session.close()
    return Response(
        content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
