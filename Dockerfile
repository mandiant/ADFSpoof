FROM python:3.11.12-slim

COPY . /app
WORKDIR /app


RUN pip install --no-cache-dir -r requirements.txt


ENTRYPOINT ["python", "/app/ADFSpoof.py"]