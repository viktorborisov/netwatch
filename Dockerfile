FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3
COPY app.py /app/app.py
ENV EVENTS_FILE=/data/events.jsonl RING_SIZE=1000 RECENT_N=200
EXPOSE 8000
CMD ["python3", "/app/app.py"]
