# build context = repo root
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 tcpdump && rm -rf /var/lib/apt/lists/*
COPY sniffer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/pg_common ./pg_common
COPY sniffer/ .
RUN mkdir -p samples && python make_sample_pcap.py
EXPOSE 8001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8001/health')"
CMD ["python", "sniffer.py"]
