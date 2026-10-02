FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 firewall
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY . .
USER firewall
EXPOSE 8120
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8120"]
