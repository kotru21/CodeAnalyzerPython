FROM python:3.14-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/analyzer/__init__.py src/analyzer/__init__.py
RUN pip install --no-cache-dir --prefix=/install .

COPY . .
RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.14-slim AS runtime

WORKDIR /app

RUN useradd --create-home --uid 10001 analyzer

COPY --from=builder /install /usr/local
COPY --chown=analyzer:analyzer data ./data
COPY --chown=analyzer:analyzer src ./src
COPY --chown=analyzer:analyzer alembic ./alembic
COPY --chown=analyzer:analyzer alembic.ini ./
COPY --chown=analyzer:analyzer pyproject.toml ./

ENV PYTHONPATH=/app/src
USER analyzer

EXPOSE 8000

CMD ["uvicorn", "analyzer.main:app", "--host", "0.0.0.0", "--port", "8000"]
