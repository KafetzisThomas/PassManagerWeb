#!/usr/bin/env bash

# Exit on error
set -o errexit

# Collect static files
python manage.py collectstatic --noinput

# Change ownership of static files
chown -R appuser:appuser /app/staticfiles

# Apply database migrations
python manage.py migrate --noinput

# Start gunicorn
python -m gunicorn --bind 0.0.0.0:8000 --workers 3 main.wsgi:application
