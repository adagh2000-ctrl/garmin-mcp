FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server_oauth.py .
CMD ["python", "server_oauth.py"]
