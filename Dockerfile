FROM python:3.11-slim

WORKDIR /app

# Copy only core backend files
COPY pyproject.toml .
COPY lumen_config.py .
COPY lumen_handshake.py .
COPY lumen_tools.py .
COPY lumen_sdk.py .
COPY lumen_engine.py .
COPY lumen_custom_plugin_demo.py .
COPY lumen_http_bridge.py .
COPY mcp_config.json .
COPY lumen_client_integration_manual.md .

# Install editable package using standard library
RUN pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["python3", "lumen_http_bridge.py", "--host", "0.0.0.0", "--port", "8080"]
