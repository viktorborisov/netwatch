FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3
COPY app.py /app/app.py
COPY ipdb.py /app/ipdb.py
# ipdb.bin (~25MB) — компактная IP->страна база (см. tools/build_ipdb.py).
# Кладём в образ, чтобы не тянуть данные по сети на старте.
COPY ipdb.bin /app/ipdb.bin
# статика: Leaflet (js/css) и контуры стран world.geo.json — без CDN
COPY static /app/static
ENV EVENTS_FILE=/data/events.jsonl IPDB_PATH=/app/ipdb.bin STATIC_DIR=/app/static RING_SIZE=1000 RECENT_N=200
EXPOSE 8000
CMD ["python3", "/app/app.py"]
