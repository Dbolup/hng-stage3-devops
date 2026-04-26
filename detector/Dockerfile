FROM python:3.11-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' detector

COPY requirements.txt .
# hadolint ignore=DL3013
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/detector && \
    chown -R detector:detector /app /var/log/detector

USER detector

EXPOSE 8080

CMD ["python", "main.py"]
