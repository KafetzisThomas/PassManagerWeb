#!/usr/bin/env bash

# Exit on error
set -o errexit

# Collect static files
uv run manage.py collectstatic --noinput

# Change ownership of static files
chown -R appuser:appuser /app/staticfiles

# Apply database migrations
uv run manage.py migrate --noinput

# Start gunicorn
uv run -m gunicorn --bind 0.0.0.0:8000 --workers 3 main.wsgi:application
