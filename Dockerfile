FROM python:3.13-slim-bookworm

WORKDIR /app

# Install dependencies in a separate layer so they're cached across code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bluetti_monitor/ bluetti_monitor/

# Run as a non-root user
RUN useradd -r bluetti && chown -R bluetti /app
USER bluetti

ENTRYPOINT ["python", "-m", "bluetti_monitor", "mqtt", "--config", "/config/config.yml"]
