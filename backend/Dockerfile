FROM python:3.11-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_lg \
    && find /usr/local -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local -type f -name "*.pyc" -delete \
    && rm -rf /root/.cache /tmp/*
COPY . .
# Data directory the API writes to. A named Docker volume mounted here (AWS deploy) copies this owner on first use.
RUN mkdir -p /srv/data && chown app:app /srv/data
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
