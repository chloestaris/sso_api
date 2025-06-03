# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Install system dependencies including curl for health checks
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create instance directory with proper permissions
RUN mkdir -p instance && \
    chmod 700 instance && \
    chown -R nobody:nogroup instance

# Set environment variables
ENV FLASK_APP=app.py \
    FLASK_ENV=development \
    FLASK_DEBUG=1 \
    SECRET_KEY=your-secret-key-change-in-production

# Switch to non-root user
USER nobody

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["flask", "run", "--host=0.0.0.0"] 