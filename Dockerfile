FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py constants.py LICENSE ./
COPY solvetls ./solvetls

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 80 443

CMD ["python", "main.py"]
