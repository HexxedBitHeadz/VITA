FROM python:3.9-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    clamav \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Allow Docker to run inside container
VOLUME /var/run/docker.sock /var/run/docker.sock

# Update ClamAV database
RUN freshclam || true

# Download and prepare YARA rules
RUN mkdir -p /app/yara-rules/packages/full && \
    wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip -O /tmp/yara-rules.zip && \
    unzip /tmp/yara-rules.zip -d /tmp/yara-temp && \
    mv /tmp/yara-temp/* /app/yara-rules/packages/full/ && \
    rm -rf /tmp/yara-rules.zip /tmp/yara-temp


# Download and install CAPA
RUN curl -L -o /tmp/capa.zip https://github.com/mandiant/capa/releases/download/v8.0.1/capa-v8.0.1-linux.zip && \
    unzip /tmp/capa.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/capa && \
    rm /tmp/capa.zip

# Install Python dependencies
RUN pip install --no-cache-dir flask werkzeug yara-python oletools networkx matplotlib


# Set the working directory
WORKDIR /app

# Copy application code into the container
COPY . /app

# Expose the port
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
