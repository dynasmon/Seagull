FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN addgroup --system --gid 10002 seagull-pki \
    && adduser --system --uid 10002 --ingroup seagull-pki seagull-pki

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY signer ./signer

EXPOSE 8460

USER 10002:10002

CMD ["python", "-m", "signer"]
