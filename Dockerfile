FROM python:3-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY m3uchop.py .

ENV M3U_EVERY=4

ENTRYPOINT ["python", "m3uchop.py"]
CMD []
