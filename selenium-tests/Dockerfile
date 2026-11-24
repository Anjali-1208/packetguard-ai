FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends chromium chromium-driver fonts-liberation && rm -rf /var/lib/apt/lists/*
WORKDIR /tests
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=300 --retries 10 -r requirements.txt
COPY . .
ENV CHROME_BIN=/usr/bin/chromium CHROMEDRIVER=/usr/bin/chromedriver
CMD ["pytest", "-v", "--junitxml=/tests/results/selenium-results.xml"]