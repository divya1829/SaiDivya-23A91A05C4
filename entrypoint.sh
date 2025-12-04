#!/usr/bin/env sh
set -e

# Start cron service
cron

# Start FastAPI server on port 8080
exec uvicorn app:app --host 0.0.0.0 --port 8080
