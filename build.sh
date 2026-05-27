#!/usr/bin/env bash
set -o errexit

uv sync --frozen

uv run python manage.py collectstatic --no-input

uv run python manage.py migrate
