FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 assesspilot && mkdir /data && chown assesspilot /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY assesspilot ./assesspilot
COPY examples ./examples
USER assesspilot
ENV ASSESSPILOT_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "assesspilot.api:app", "--host", "0.0.0.0", "--port", "8000"]
