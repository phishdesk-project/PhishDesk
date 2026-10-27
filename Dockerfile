FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.lock pyproject.toml README.md LICENSE ./
RUN pip install -r requirements.lock
COPY src ./src
COPY deploy/logging.json ./deploy/logging.json
RUN pip install --no-deps . && useradd --uid 10001 --create-home phishdesk
USER 10001
EXPOSE 8000
CMD ["uvicorn", "phishdesk.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-config", "deploy/logging.json"]
