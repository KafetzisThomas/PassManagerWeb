# Stage 1: Base build stage
FROM python:3.10-slim AS builder

# Create the app directory
RUN mkdir /app

# Set the working directory
WORKDIR /app

# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1 

# Install dependencies first for caching benefit
RUN pip install --upgrade pip 
COPY requirements.txt /app/ 
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Production stage
FROM python:3.10-slim

RUN useradd -m -r appuser && \
    mkdir /app && \
    chown -R appuser /app

# Copy the Python dependencies from the builder stage
COPY --from=builder /usr/local/lib/python3.10/site-packages/ /usr/local/lib/python3.10/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Set the working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser . .

# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1 

# Create the staticfiles directory
RUN mkdir -p /app/staticfiles && chown appuser:appuser /app/staticfiles

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000 

# Make entry file executable
RUN chmod +x  /app/entrypoint.prod.sh

# Start the application using Gunicorn
CMD ["/app/entrypoint.prod.sh"]
