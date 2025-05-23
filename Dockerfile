# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create instance directory if it doesn't exist
RUN mkdir -p instance

# Expose port 5000
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
# Default to production, but allow override
ENV FLASK_ENV=${FLASK_ENV:-production}
ENV FLASK_DEBUG=${FLASK_DEBUG:-0}

# Run the application with hot reload in development
CMD if [ "$FLASK_ENV" = "development" ]; then \
        flask run --host=0.0.0.0 --reload --debugger; \
    else \
        flask run --host=0.0.0.0; \
    fi 