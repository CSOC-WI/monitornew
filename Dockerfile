FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY security_news.py .
COPY notifier.py      .
COPY scheduler.py     .
COPY web.py           .

EXPOSE 8080

CMD ["python3", "web.py", "--host", "0.0.0.0", "--port", "8080"]
