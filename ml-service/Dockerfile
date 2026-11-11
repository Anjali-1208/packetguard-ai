# build context = repo root (so shared/ can be copied in)
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
COPY ml-service/requirements.txt .
RUN pip install --no-cache-dir --default-timeout=300 --retries 10 -r requirements.txt
COPY shared/pg_common ./pg_common
COPY ml-service/ .
# Bundle trained model artifacts into the image at build time. Drop a real CIC-IDS2017 CSV
# into ./data and set DATASET_CSV (see README) to train on real data instead of synthetic.
COPY data/ ./data/
ARG DATASET_CSV=
ENV DATASET_CSV=${DATASET_CSV}
RUN python train.py
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]