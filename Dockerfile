FROM node:22-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    STATIC_DIR=/app/static \
    DATABASE_URL=sqlite:////app/data/xcheck.db
WORKDIR /app
RUN groupadd --system xcheck && useradd --system --gid xcheck --home-dir /app xcheck
COPY pyproject.toml LICENSE NOTICE ./
COPY backend/ ./backend/
RUN pip install --no-cache-dir .
COPY --from=frontend-build /build/frontend/dist ./static/
RUN mkdir -p /app/data && chown -R xcheck:xcheck /app
USER xcheck
EXPOSE 8086
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8086/api/health', timeout=3)" || exit 1
CMD ["uvicorn", "xcheck.main:app", "--host", "0.0.0.0", "--port", "8086", "--workers", "1"]
