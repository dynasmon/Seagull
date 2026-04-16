FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN addgroup --system --gid 10001 seagull \
    && adduser --system --uid 10001 --ingroup seagull seagull

COPY requirements.lock requirements-dev.txt requirements.txt alembic.ini ./
COPY alembic ./alembic
RUN pip install --no-cache-dir -r requirements.lock

COPY app ./app

EXPOSE 8000

USER 10001:10001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
