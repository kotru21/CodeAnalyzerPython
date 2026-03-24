FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/analyzer/__init__.py src/analyzer/__init__.py
RUN pip install --no-cache-dir ".[dev]"

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "analyzer.main:app", "--host", "0.0.0.0", "--port", "8000"]
