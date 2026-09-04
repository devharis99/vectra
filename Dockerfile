FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VECTRA_DATA_DIR=/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY vectra/ /app/vectra/

RUN pip install --no-cache-dir -e .

VOLUME ["/data"]

ENTRYPOINT ["vectra"]
CMD ["interactive"]
